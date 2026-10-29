# shellcheck shell=bash
# cp-import.sh step: creating the OpenPanel account and restoring its files and settings, sourced by cp-import.sh

validate_plan_exists(){
	opencli plan-list --json | grep -qw "$plan_name" || { log "FATAL ERROR: Plan name '$plan_name' does not exist."; exit 1; }
}

reload_user_quotas() {
	dry_run "Would reload quotas for all users" && return
	nohup bash -c 'opencli user-quota' >/dev/null 2>&1 &
	disown
}

collect_stats() {
	dry_run "Would collect resource usage stats for user $cpanel_username" && return
    nohup bash -c "opencli docker-collect_stats '$cpanel_username'" >/dev/null 2>&1 &
	disown
}

# ======================================================================
# CHECK USERNAME AVIABILITY BEFORE SGTARTING THE EXPORT PROCESS
check_if_user_exists(){
    backup_filename=$(basename "$backup_location")
    cpanel_username="${backup_filename##*_}"
    cpanel_username="${cpanel_username%%.*}"
    # WHM transfers and pkgacct name the file cpmove-<user>.tar.gz
    cpanel_username="${cpanel_username#cpmove-}"
    log "Username: $cpanel_username"

    local existing_user=""
	existing_user=$(opencli user-list --json | jq -r '.data[] | select(.username == "'"$cpanel_username"'") | .id')

	if [ -n "$existing_user" ]; then
        log "FATAL ERROR: $cpanel_username already exists."
        exit 1
	fi

    log "Username $cpanel_username is available"
	log "Starting import process.."
}

# ======================================================================
# CREATE OPENPANEL USER
create_new_user() {
    local username="$1"
    local email="$3"
    local plan_name="$4"
	local reseller_arg=""

	dry_run "Would create user $username${reseller:+ for reseller $reseller} with email $email and plan $plan_name" && return

	if [ -n "$reseller" ]; then
	    log "Creating openpanel user for reseller $reseller and configuring services.."
	    reseller_arg="--reseller=$reseller"
	else
	    log "Creating openpanel user and configuring services.."
	fi

	create_user_command=$(opencli user-add "$cpanel_username" generate "$email" "$plan_name" $reseller_arg --no-sentinel 2>&1)
	local user_add_status=$?

    while IFS= read -r line; do
        log "$line"
    done <<< "$create_user_command"

	# user-add can fail after it already wrote docker-compose.yml, so check its exit code and the account
	if [ "$user_add_status" -ne 0 ] || ! id -u "$cpanel_username" >/dev/null 2>&1; then
        cleanup
        # last line of the log, so OpenAdmin shows the import as failed
        log "FATAL ERROR: User addition failed."
        exit 1
    fi

    shadow_file="$real_backup_files_path/shadow"
    if [ -f "$shadow_file" ]; then
        . /usr/local/opencli/db.sh

        hashed_password=$(cat "$shadow_file")
        safe_hashed_password=$(printf "%s" "$hashed_password" | sed "s/'/''/g")
        safe_username=$(printf "%s" "$username" | sed "s/'/''/g")
        mysql_query="UPDATE users SET password='$safe_hashed_password' WHERE username='$safe_username';"
        mysql --defaults-extra-file="$config_file" -D "$mysql_database" -e "$mysql_query"
        if [ $? -eq 0 ]; then
            echo "Imported SHA-512 crypt password hash from cpanel (will be automatically converted to pbkdf2:sha256 on first user login)"
        else
            echo "Failed to import SHA-512 crypt password hash from cpanel"
        fi
    fi
}

# ======================================================================
# PHP VERSION
restore_php_version() {
    local php_version="$1"

    dry_run "Would set default PHP version $php_version for user $cpanel_username" && return

    # 'inherit' = OpenPanel default
    if [ "$php_version" == "inherit" ]; then
        log "PHP version is set to inherit. No changes will be made."
    else
        # cPanel custom version
        #log "Setting PHP $php_version as the default version for all new domains."
        output=$(opencli php-default "$cpanel_username" --update "$php_version" 2>&1)
        while IFS= read -r line; do
            log "$line"
        done <<< "$output"
    fi
}

create_home_mountpoint() {
    dry_run "Would create a symlink from html_data volume to /home/$cpanel_username/" && return
    
sed -i '/^[[:space:]]*volumes:[[:space:]]*$/{
  N
  /- html_data:\/var\/www\/html\// s|$|\n      - html_data:/home/${CONTEXT}/|
}' /home/$cpanel_username/docker-compose.yml

}

# ======================================================================
# HOME DIR
restore_files() {
    dry_run "Would restore files from /home/$cpanel_username/ to html_data volume" && return

    du_needed_for_home=$(du -sh "$real_backup_files_path/homedir" | cut -f1)
    log "Restoring home directory ($du_needed_for_home) to html_data volume"
    local data_dir="/home/$cpanel_username/docker-data/volumes/${cpanel_username}_html_data/_data"
    mkdir -p "$data_dir"
    rm -rf "$real_backup_files_path"/homedir/{.cpanel,.trash,wordpress-backups}
    # move into the _data dir user-add made, replacing the dir would leave already started containers on the old one
    (shopt -s dotglob nullglob; mv -- "$real_backup_files_path"/homedir/* "$data_dir"/) || rsync -a "$real_backup_files_path/homedir/" "$data_dir/"
    # cPanel lets the webserver into docroots via group nobody, which the chown below drops, so open those to others
    local nobody_gid
    nobody_gid=$(getent group nobody | cut -d: -f3)
    find "$data_dir" \( -gid 99 -o -gid 65534 ${nobody_gid:+-o -gid "$nobody_gid"} \) -exec chmod o+rX {} +
    # same permissions and owner user-add gives the volume
    chmod -R g+w "$data_dir"
    chown -R "$cpanel_username:$cpanel_username" "$data_dir"
}

# ======================================================================
# PERMISSIONS
fix_perms(){
    local verbose="" #-v
    log "Changing permissions for all files and folders in user home directory /home/$cpanel_username/"

    dry_run "Would change permissions with command: find /home/$cpanel_username -print0 | xargs -0 chown $verbose $cpanel_username:$cpanel_username" && return
    chown -R $cpanel_username:$cpanel_username /home/$cpanel_username     
}

# LOCAE
restore_locale() {
    if [ -f "$real_backup_files_path/cp/$cpanel_username" ]; then
        local file_path="$real_backup_files_path/cp/$cpanel_username"
    	local locale_code=$(grep '^LOCALE=' "$file_path" | cut -d'=' -f2 | cut -c1-2 | tr '[:upper:]' '[:lower:]')
	    if [ "$locale_code" = "en" ] || [ -d "/etc/openpanel/openpanel/translations/$locale_code" ]; then
			dry_run "Would set locale:$locale_code for OpenPanel UI" && return
			log "Setting locale:$locale_code for OpenPanel UI"
			echo "$locale_code" > /home/$cpanel_username/locale
		else
			log "Skipping user locale: '$locale_code' is not available"
		fi
	fi
}

# ======================================================================
# POST-IMPORT HOOK
run_custom_post_hook() {
    if [ -n "$post_hook" ]; then
        if [ -x "$post_hook" ]; then
            dry_run "Would run post-hook script $post_hook" && return
            log "Executing post-hook script.."
            "$post_hook" "$cpanel_username"
        else
            log "WARNING: Post-hook file '$post_hook' is not executable or not found."
            exit 1
        fi
    fi
}

# ======================================================================
# CREATED DATE IN OPENADMIN FROM WHM
restore_startdate() {
    real_backup_files_path="$1"
    cpanel_username="$2"
    cp_file_path="$real_backup_files_path/cp/$cpanel_username"
    STARTDATE=$(grep -oP 'STARTDATE=\K\d+' "$cp_file_path")
    
    if [ -n "$STARTDATE" ]; then
      human_readable_date=$(date -d @"$STARTDATE" +"%Y-%m-%d %H:%M:%S")
      dry_run "Would set account creation date to cpanel date: $human_readable_date" && return
      log "Updating account creation date to reflect cpanel date: $human_readable_date"
      update_timestamp="UPDATE users SET registered_date = '$human_readable_date' WHERE username = '$cpanel_username';"
      mysql -e "$update_timestamp"
    fi
}

# ======================================================================
# EMAIL NOTIFICATIONS
restore_notifications() {
    local real_backup_files_path="$1"
    local cpanel_username="$2"
    notifications_cp_file="$real_backup_files_path/cp/$cpanel_username"
    notifications_op_file="/etc/openpanel/openpanel/core/users/$cpanel_username/notifications.yaml"
   
    if [ ! -f "$notifications_cp_file" ]; then
        log "WARNING: Unable to access $notifications_cp_file for notification preferences - Skipping"
    else
        dry_run "Would restore notification preferences from $notifications_cp_file" && return

		grep "notify_" "$notifications_cp_file" > "$notifications_op_file" || true
        cat_notifications_file=$(cat $notifications_op_file 2>&1)
        while IFS= read -r line; do
            log "$line"
        done <<< "$cat_notifications_file"
    fi
}

write_import_activity() {
    dry_run "Would write the import to /etc/openpanel/openpanel/core/users/$cpanel_username/activity.log" && return
    echo "$(date '+%Y-%m-%d %H:%M:%S')  $new_ip  Administrator ROOT user imported cpanel backup file" > /etc/openpanel/openpanel/core/users/$cpanel_username/activity.log
}
