# shellcheck shell=bash
# cp-import.sh step: MySQL/MariaDB and PostgreSQL databases, users and grants, sourced by cp-import.sh

get_mysql_type_cnf_and_socket() {
    mysql_type=$(grep '^MYSQL_TYPE=' /home/$cpanel_username/.env | cut -d '=' -f2 | tr -d '"')
	mysql_socket="/home/$cpanel_username/sockets/mysqld/mysqld.sock"
	mysql_cnf="/home/$cpanel_username/my.cnf"
}

# ======================================================================
# POSTGRESQL
restore_psql() {
	local psql_dir="$1"
    log "Restoring PostgreSQL databases"
    dry_run "Would restore PostgreSQL databases for user $cpanel_username" && return

	if [ -n "$(ls -A $psql_dir 2>/dev/null)" ]; then
        # STEP 1: Start psql container
        log "Initializing postgres service for user"
        cd "/home/$cpanel_username/" && CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman-compose up -d postgres >/dev/null 2>&1

        # STEP 2: Wait for PostgreSQL to be ready (max 300 seconds)
		local max_wait=300
        log "Waiting for PostgreSQL service to start... (max ${max_wait}s)"
        waited=0		
		while ! CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman exec postgres psql -U postgres -d "$postgres" -c "SELECT 1;" >/dev/null 2>&1; do
            sleep 2
            waited=$((waited + 2))
            if [ "$waited" -ge "$max_wait" ]; then
                log "ERROR: postgres did not respond to 'SELECT 1' after $max_wait seconds - no database or users are imported"			
                return 1
            fi
        done
        log "postgres is ready after $waited seconds"

        # STEP 3: Create and import databases
        total_databases=$(ls "$psql_dir"/*.tar 2>/dev/null | wc -l)
        log "Starting import for $total_databases PostgreSQL databases"
        if [ "$total_databases" -gt 0 ]; then
            current_db=1
            for db_file in "$psql_dir"/*.tar; do
                db_name=$(basename "$db_file" .tar)

                log "Creating database: $db_name (${current_db}/${total_databases})"
				CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman exec postgres psql -U postgres -c "CREATE DATABASE \"$db_name\";" #>/dev/null 2>&1

                log "Importing tables for database: $db_name"
                CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman cp "${real_backup_files_path}/psql/$db_name.tar" "postgres:/tmp/${db_name}.tar" >/dev/null 2>&1		
				CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman exec postgres bash -c "cd /tmp && tar -xf /tmp/${db_name}.tar restore.sql && psql -U postgres -d \"$db_name\" -f restore.sql && rm restore.sql /tmp/${db_name}.tar"
                current_db=$((current_db + 1))
            done
            log "Finished processing $((current_db - 1)) databases"
        else
            log "WARNING: No PostgreSQL databases found"
        fi

		# psql_users.sql
		if [[ -f "$psql_users" && -s "$psql_users" ]]; then
			log "Importing database users"
		    while IFS= read -r line || [[ -n "$line" ]]; do
		        [[ -z "$line" ]] && continue
		        CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman exec postgres psql -U postgres -d postgres -c "$line"
		    done < "$psql_users"
		else
		    echo "WARNING: No PostgreSQL USERS detected"
		fi

        # psql_grants.sql
		if [[ -f "$psql_grants" && -s "$psql_grants" ]]; then
			log "Importing database grants"
		    while IFS= read -r line || [[ -n "$line" ]]; do
		        [[ -z "$line" ]] && continue
		        CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman exec postgres psql -U postgres -d postgres -c "$line"
		    done < "$psql_grants"
		else
		    echo "WARNING: No PostgreSQL GRANTS detected"
		fi

    else
        log "No PostgreSQL databases found to restore"
    fi


}

# ======================================================================
# MYSQL
restore_mysql() {
    local mysql_dir="$1"
    local sandbox_warning_logged=false

    log "Restoring MySQL databases"
    dry_run "Would restore MySQL databases for user $cpanel_username" && return

    # Workaround for MariaDB sandbox mode bug
    apply_sandbox_workaround() {
        local db_file="$1"
        local text_to_check='enable the sandbox mode'
        local first_line

        first_line=$(head -n 1 "${real_backup_files_path}/mysql/$db_file")
        if echo "$first_line" | grep -q "$text_to_check"; then
            if [ "$sandbox_warning_logged" = false ]; then
                log "WARNING: Database dumps were created on a MariaDB server with '--sandbox' mode. Applying workaround for backwards compatibility to MySQL (BUG: https://jira.mariadb.org/browse/MDEV-34183)"
                sandbox_warning_logged=true
            fi
            tail -n +2 "${real_backup_files_path}/mysql/$db_file" > "${real_backup_files_path}/mysql/${db_file}.workaround" && mv "${real_backup_files_path}/mysql/${db_file}.workaround" "${real_backup_files_path}/mysql/$db_file"
        fi
    }

	# STEP 1: Enable remote access
	if [ -f "${real_backup_files_path}/mysql_host_notes.json" ]; then
		key_count=$(jq 'keys | length' "${real_backup_files_path}/mysql_host_notes.json")
		if [ "$key_count" -gt 0 ]; then
			log "Enabling remote MySQL access ($key_count hosts detected)"
			sed -i '/^MYSQL_PORT=/ s/127\.0\.0\.1://g' /home/$cpanel_username/.env
		fi
	fi

	if [ ! -n "$(ls -A $mysql_dir 2>/dev/null)" ]; then
		log "No MySQL databases found to restore"
		return
	fi
	
	# STEP 2: Start MySQL container
	if [ "$mysql_type" = "mysql" ]; then
		mysql_version="8.0"
		sed -i 's/^MYSQL_VERSION=.*/MYSQL_VERSION="8.0"/' /home/"$cpanel_username"/.env
	fi

	log "Initializing $mysql_type service for user"
	cd "/home/$cpanel_username/" && CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman-compose up -d "$mysql_type" >/dev/null 2>&1

	# STEP 3: Replace old IP and hostname
	old_ip=$(grep -oP 'IP=\K[0-9.]+' "${real_backup_files_path}/cp/$cpanel_username")
	if [ -z "$old_ip" ]; then
	    log "WARNING: old server ip address not detected in cp file - grants will not be updated to '%'."
	else
	    log "Replacing old server IP: $old_ip with '%' in database grants"
	    sed -i "s/$old_ip/%/g" "$mysql_conf"
	fi

	old_hostname=$(cat "${real_backup_files_path}/meta/hostname")
	log "Removing old hostname $old_hostname from database grants"
	sed -i "/$old_hostname/d" "$mysql_conf"

	# STEP 4: Wait for MySQL to be ready (max 300 seconds)
	local max_wait=300
	log "Waiting for MySQL service to start... (max ${max_wait}s)"
	waited=0
	# on first start the image's entrypoint runs a temporary init server with skip_networking and stops it again, so wait for the real one
	while [ "$(mysql --defaults-file="$mysql_cnf" --socket="$mysql_socket" -N -B --execute="SELECT @@skip_networking;" 2>/dev/null)" != "0" ]; do
		sleep 2
		waited=$((waited + 2))
		if [ "$waited" -ge "$max_wait" ]; then
			log "ERROR: $mysql_type did not finish starting after $max_wait seconds - no database or users are imported"
			return 1
		fi
	done
	log "$mysql_type is ready after $waited seconds"

	# STEP 5: Create and import databases
	total_databases=$(ls "$mysql_dir"/*.create 2>/dev/null | wc -l)
	log "Starting import for $total_databases MySQL databases"
	if [ "$total_databases" -gt 0 ]; then
		current_db=1
		for db_file in "$mysql_dir"/*.create; do
			db_name=$(basename "$db_file" .create)

			log "Creating database: $db_name (${current_db}/${total_databases})"
			[ "$mysql_type" = "mysql" ] && apply_sandbox_workaround "$db_name.create"
			mysql --defaults-file="$mysql_cnf" --socket="$mysql_socket" < "${real_backup_files_path}/mysql/$db_name.create" && echo "Database: $db_name - Create OK" || echo "Database: $db_name - Create FAILED"

			log "Importing tables for database: $db_name"
			[ "$mysql_type" = "mysql" ] && apply_sandbox_workaround "$db_name.sql"
			mysql --defaults-file="$mysql_cnf" --socket="$mysql_socket" "$db_name" < "${real_backup_files_path}/mysql/$db_name.sql" && echo "Database: $db_name - Import tables OK" || echo "Database: $db_name - Import tables FAILED"

			current_db=$((current_db + 1))
		done
		log "Finished processing $((current_db - 1)) databases"
	else
		log "WARNING: No MySQL databases found"
	fi

	# STEP 6: Import grants
	log "Importing database grants"
	python3 "$script_dir/mysql/json_2_sql.py" "${real_backup_files_path}/mysql.sql" "${real_backup_files_path}/mysql.TEMPORARY.sql" >/dev/null 2>&1
	mysql --defaults-file="$mysql_cnf" --socket="$mysql_socket" < "${real_backup_files_path}/mysql.TEMPORARY.sql" && mysql --defaults-file="$mysql_cnf" --socket="$mysql_socket" -e "FLUSH PRIVILEGES;" && echo "Import grants OK" || { echo "Import grants FAILED"; }

}
