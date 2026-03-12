#!/bin/bash
pid=$$
script_dir=$(dirname "$0")
timestamp="$(date +'%Y-%m-%d_%H-%M-%S')"
start_time=$(date +%s)
DEBUG=true



# ======================================================================
# START HELPER FUNCTIONS

usage() {
    echo "Usage: $0 --backup-location='<path>' --plan-name='<plan_name>' [--dry-run]"
    echo
    echo "Example: $0 --backup-location='/home/backup-7.29.2024_13-22-32_pejcic.tar.gz' --plan-name='Standard plan' --dry-run"
    exit 1
}

log() {
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

debug_log() {
    if [ "$DEBUG" = true ]; then
        log "DEBUG: $1"
    fi
}

dry_run() {
    local msg="$1"
    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: $msg"
        return 0
    fi
    return 1
}

handle_error() {
    log "FATAL ERROR: An error occurred in function '$1' on line $2"
    cleanup
    exit 1
}

trap 'handle_error "${FUNCNAME[-1]}" "$LINENO"' ERR

cleanup() {
    log "Cleaning up temporary files and directories"
    rm -rf "$backup_dir"
}

define_data_and_log(){
    local backup_location=""
    plan_name=""
    DRY_RUN=false

    for arg in "$@"; do
        case $arg in
            --backup-location=*) backup_location="${arg#*=}" ;;
            --plan-name=*)       plan_name="${arg#*=}" ;;
            --dry-run)           DRY_RUN=true ;;
            --post-hook=*)       post_hook="${arg#*=}" ;;
            *)                   usage ;;
        esac
    done

	[[ -z "$backup_location" || -z "$plan_name" ]] && usage

    base_name="$(basename "$backup_location")"
    base_name_no_ext="${base_name%.*}"
    local log_dir="/var/log/openpanel/admin/imports"
    mkdir -p $log_dir
    LOG_FILE="$log_dir/${base_name_no_ext}_${timestamp}.log"
    echo "Import started, log file: $LOG_FILE"
    main
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_dependencies() {
    log "Checking and installing dependencies..."
    install_needed=false
    commands=(tar unzip jq pigz wget curl)

    for cmd in "${commands[@]}"; do
        command_exists "$cmd" || { install_needed=true; break; }
    done

    if [ "$install_needed" = true ]; then
        if command_exists apt-get; then
            log "Detected APT package manager. Updating..."
            apt-mark hold linux-image-generic linux-headers-generic >/dev/null 2>&1
            apt-get update -y >/dev/null 2>&1
            for cmd in "${commands[@]}"; do
                if ! command_exists "$cmd"; then
                    log "Installing $cmd (APT)"
                    apt-get install -y --no-upgrade --no-install-recommends "$cmd" >/dev/null 2>&1
                fi
            done
            apt-mark unhold linux-image-generic linux-headers-generic >/dev/null 2>&1
        elif command_exists dnf; then
            log "Detected DNF package manager. Updating..."
            dnf -y makecache >/dev/null 2>&1
            for cmd in "${commands[@]}"; do
                if ! command_exists "$cmd"; then
                    log "Installing $cmd (DNF)"
                    dnf install -y "$cmd" >/dev/null 2>&1
                fi
            done
        else
            log "Error: Unsupported package manager. Please install dependencies manually."
            exit 1
        fi
        log "Dependencies installed successfully."
    else
        log "All required dependencies are already installed."
    fi
}

get_server_ipv4(){
    new_ip=$(curl --silent --max-time 2 -4 https://ip.openpanel.com || curl --silent --max-time 2 -4 https://ifconfig.me)
    if [ -z "$new_ip" ]; then
        new_ip=$(ip addr|grep 'inet '|grep global|head -n1|awk '{print $2}'|cut -f1 -d/)
    fi
}

validate_plan_exists(){
	opencli plan-list --json | grep -qw "$plan_name" || { log "FATAL ERROR: Plan name '$plan_name' does not exist."; exit 1; }
}

# END HELPER FUNCTIONS
# ======================================================================



# ======================================================================
# CHECK BACKUP FILE EXTENSION AND DETERMINE SIZE NEEDED FOR RESTORE
check_if_valid_cp_backup() {
    local backup_location="$1"
    local backup_filename
    backup_filename=$(basename "$backup_location")

    ARCHIVE_SIZE=$(stat -c%s "$backup_location")

    extraction_command="tar -xzf"
    multiplier=2

    case "$backup_filename" in
        cpmove-*.tar.gz) log "Identified cpmove backup" ;;
        backup-*.tar.gz|*.tar.gz) log "Identified gzipped tar backup" ;;
        *.tgz) log "Identified tgz backup"; multiplier=3 ;;
        *.tar) log "Identified tar backup"; extraction_command="tar -xf"; multiplier=3 ;;
        *.zip) log "Identified zip backup"; extraction_command="unzip"; multiplier=3 ;;
        *) log "FATAL ERROR: Unrecognized backup format: $backup_filename"; exit 1 ;;
    esac

    EXTRACTED_SIZE=$((ARCHIVE_SIZE * multiplier))
}

# ======================================================================
# CHECK AVAILABLE DISK SPACE ON THE OPENPANEL SERVER
check_if_disk_available(){
    TMP_DIR="/tmp"
    HOME_DIR="/home"
    AVAILABLE_TMP=$(df -B1 --output=avail "$TMP_DIR" | tail -n 1)
    AVAILABLE_HOME=$(df -B1 --output=avail "$HOME_DIR" | tail -n 1)

    if [[ $AVAILABLE_TMP -ge $EXTRACTED_SIZE && $AVAILABLE_HOME -ge $EXTRACTED_SIZE ]]; then
        log "There is enough disk space to extract the archive and copy it to the home directory."
    else
        log "FATAL ERROR: Not enough disk space."
        if [[ $AVAILABLE_TMP -lt $EXTRACTED_SIZE ]]; then
            log "Insufficient space in the '/tmp' partition."
            log "Available: $AVAILABLE_TMP - Needed: $EXTRACTED_SIZE"
        fi
        if [[ $AVAILABLE_HOME -lt $EXTRACTED_SIZE ]]; then
            log "Insufficient space in the '/home' directory."
            log "Available: $AVAILABLE_HOME - Needed: $EXTRACTED_SIZE"
        fi
        exit 1
    fi
}

# ======================================================================
# EXTRACT BACKUP TO TMP LOCATION
extract_cyberpanel_backup() {
    backup_location="$1"
    backup_dir="$2"
    backup_dir="${backup_dir%.*}"
    log "Extracting backup from $backup_location to $backup_dir"
    mkdir -p "$backup_dir"

    if [ "$extraction_command" = "unzip" ]; then
        $extraction_command "$backup_location" -d "$backup_dir"
    elif [ "$extraction_command" = "tar -xzf" ]; then
        backup_size=$(stat -c %s "${backup_location}")
        zero_one_percent=$((backup_size / 1000000))
        tar --use-compress-program=pigz \
            --checkpoint="$zero_one_percent" \
            --checkpoint-action=dot \
            -xf "$backup_location" \
            -C "$backup_dir" 
    else
        $extraction_command "$backup_location" -C "$backup_dir"
    fi
    
    if [ $? -eq 0 ]; then
        log "Backup extracted successfully."
        log "Extracted backup folder: $real_backup_files_path"
    else
        log "FATAL ERROR: Backup extraction failed."
        cleanup
        exit 1
    fi
}

get_mariadb_or_mysql_for_user() {
    mysql_type=$(grep '^MYSQL_TYPE=' /home/$cyberpanel_username/.env | cut -d '=' -f2 | tr -d '"')

    if [[ "$mysql_type" != "mariadb" && "$mysql_type" != "mysql" ]]; then
        echo "Unsupported MYSQL_TYPE: $mysql_type"
        exit 1
    fi
}

reload_user_quotas() {
	nohup bash -c 'quotacheck -avm && repquota -u / > /etc/openpanel/openpanel/core/users/repquota' >/dev/null 2>&1 &
	disown
}

collect_stats() {
    nohup bash -c "opencli docker-collect_stats '$cyberpanel_username'" >/dev/null 2>&1 &
	disown
}

# ======================================================================
# PARSE CPANEL BACKUP METADATA FOR ACCOUNT AND SERVICE INFORMATION
parse_metadata() {
    log "Starting to parse cPanel metadata from meta.xml..."

    meta_file="${real_backup_files_path}/meta.xml"

    if [ ! -f "$meta_file" ]; then
        log "WARNING: meta.xml file $meta_file not found. Using default values."
        main_domain=""
        cyberpanel_email=""
        php_version="inherit"
		db_count=0
		email_count=0
    else

        get_xml_value() {
            local tag="$1"
            grep -oPm1 "(?<=<$tag>)[^<]+" "$meta_file"
        }
		
		cyberpanel_username=$(get_xml_value "userName")
        main_domain=$(get_xml_value "masterDomain")
        cyberpanel_email=$(get_xml_value "email")
		php_version=$(get_xml_value "phpSelection")
		php_version="${php_version#PHP }"
		db_count=$(grep -o "<dbName>" "$meta_file" | wc -l)
		email_count=$(grep -o "<emailAccount>" "$meta_file" | wc -l)
    fi

    main_domain="${main_domain:-Not found}"
    cyberpanel_email="${cyberpanel_email:-admin@$main_domain}"
    php_version="${php_version:-inherit}"
	db_count="${db_count:-0}"
	email_count="${email_count:-0}"

    log "Username:             $cyberpanel_username"
    log "Main Domain:          $main_domain"
    log "Email:                $cyberpanel_email"
    log "PHP Version:          $php_version"

    log "Additional metadata parsed:"
	log "Database Count:       $db_count"
    log "Email Account Count:  $email_count"
    log "Finished parsing CyberPanel metadata."
}

# ======================================================================
# CHECK USERNAME AVIABILITY BEFORE SGTARTING THE EXPORT PROCESS
check_if_user_exists(){
    log "Username: $cyberpanel_username"

    local existing_user=""
    existing_user=$(opencli user-list --json | jq -r ".[] | select(.username == \"$cyberpanel_username\") | .id")

	if [ -n "$existing_user" ]; then
        log "FATAL ERROR: $cyberpanel_username already exists."
		cleanup
        exit 1
	fi

    log "Username $cyberpanel_username is available"
	log "Starting import process.."
}

# ======================================================================
# CREATE OPENPANEL USER
create_new_user() {
    local username="$1"
    local email="$3"
    local plan_name="$4"

    dry_run "Would create user $username with email $email and plan $plan_name" && return
        
    create_user_command=$(opencli user-add "$cyberpanel_username" generate "$email" "$plan_name" --no-sentinel 2>&1)
    while IFS= read -r line; do
        log "$line"
    done <<< "$create_user_command"

    if echo "$create_user_command" | grep -q "Successfully added user"; then
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
    else
        log "FATAL ERROR: User addition failed. Response did not contain the expected success message."
        exit 1
    fi
}

# ======================================================================
# PHP VERSION
restore_php_version() {
    local php_version="$1"

    dry_run "Would set default PHP version $php_version for user $cyberpanel_username" && return

    # 'inherit' = OpenPanel default
    if [ "$php_version" == "inherit" ]; then
        log "PHP version is set to inherit. No changes will be made."
    else
        # cPanel custom version
        log "Setting PHP $php_version as the default version for all new domains."
        output=$(opencli php-default "$cyberpanel_username" --update "$php_version" 2>&1)
        while IFS= read -r line; do
            log "$line"
        done <<< "$output"
    fi
}

# ======================================================================
# MYSQL
restore_mysql() {
    local mysql_dir="$1"
    local sandbox_warning_logged=false

    log "Restoring MySQL databases for user $cyberpanel_username"

    dry_run "Would restore MySQL databases for user $cyberpanel_username" && return

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
            tail -n +2 "${real_backup_files_path}/mysql/$db_file" > "${real_backup_files_path}/mysql/${db_file}.workaround" && \
            mv "${real_backup_files_path}/mysql/${db_file}.workaround" "${real_backup_files_path}/mysql/$db_file"
        fi
    }

    if [ -d "$mysql_dir" ]; then
        # STEP 1: Replace old IP and hostname
        old_ip=$(grep -oP 'IP=\K[0-9.]+' "${real_backup_files_path}/cp/$cyberpanel_username")
        log "Replacing old server IP: $old_ip with '%' in database grants"
        sed -i "s/$old_ip/%/g" "$mysql_conf"

        old_hostname=$(cat "${real_backup_files_path}/meta/hostname")
        log "Removing old hostname $old_hostname from database grants"
        sed -i "/$old_hostname/d" "$mysql_conf"
        
        # STEP 2: Start MySQL container
        if [ "$mysql_type" = "mysql" ]; then
            mysql_version="8.0"
            sed -i 's/^MYSQL_VERSION=.*/MYSQL_VERSION="8.0"/' /home/"$cyberpanel_username"/.env
        fi
        log "Initializing $mysql_type $mysql_version service for user"
        cd "/home/$cyberpanel_username/" && docker --context="$cyberpanel_username" compose up -d "$mysql_type" >/dev/null 2>&1

        # STEP 3: Wait for MySQL to be ready (max 300 seconds)
        log "Waiting for MySQL service to be ready..."
        max_wait=300
        waited=0
        while ! docker --context="$cyberpanel_username" exec "$mysql_type" $mysql_type -e "SELECT 1" >/dev/null 2>&1; do
            sleep 2
            waited=$((waited + 2))
            if [ "$waited" -ge "$max_wait" ]; then
                log "ERROR: $mysql_type did not become ready after $max_wait seconds"
                exit 1
            fi
        done
        log "$mysql_type is ready after $waited seconds"

        # STEP 4: Create and import databases
        total_databases=$(ls "$mysql_dir"/*.create 2>/dev/null | wc -l)
        log "Starting import for $total_databases MySQL databases"
        if [ "$total_databases" -gt 0 ]; then
            current_db=1
            for db_file in "$mysql_dir"/*.create; do
                db_name=$(basename "$db_file" .create)

                log "Creating database: $db_name (${current_db}/${total_databases})"
                apply_sandbox_workaround "$db_name.create"
                docker --context="$cyberpanel_username" cp "${real_backup_files_path}/mysql/$db_name.create" "$mysql_type:/tmp/${db_name}.create" >/dev/null 2>&1
                docker --context="$cyberpanel_username" exec "$mysql_type" bash -c "mysql < /tmp/${db_name}.create && rm /tmp/${db_name}.create"

                log "Importing tables for database: $db_name"
                apply_sandbox_workaround "$db_name.sql"
                docker --context="$cyberpanel_username" cp "${real_backup_files_path}/mysql/$db_name.sql" "$mysql_type:/tmp/${db_name}.sql" >/dev/null 2>&1
                docker --context="$cyberpanel_username" exec "$mysql_type" bash -c "mysql $db_name < /tmp/${db_name}.sql && rm /tmp/${db_name}.sql"

                current_db=$((current_db + 1))
            done
            log "Finished processing $((current_db - 1)) databases"
        else
            log "WARNING: No MySQL databases found"
        fi

        # STEP 5: Import grants
        log "Importing database grants"
        python3 "$script_dir/mysql/json_2_sql.py" "${real_backup_files_path}/mysql.sql" "${real_backup_files_path}/mysql.TEMPORARY.sql" >/dev/null 2>&1

        docker --context="$cyberpanel_username" cp "${real_backup_files_path}/mysql.TEMPORARY.sql" "$mysql_type:/tmp/mysql.TEMPORARY.sql" >/dev/null 2>&1
        docker --context="$cyberpanel_username" exec "$mysql_type" bash -c "$mysql_type < /tmp/mysql.TEMPORARY.sql && $mysql_type -e 'FLUSH PRIVILEGES;' && rm /tmp/mysql.TEMPORARY.sql"

    else
        log "No MySQL databases found to restore"
    fi
}

# ======================================================================
# SSL CERTIFICATES
restore_ssl() {
    local username="$1"

    dry_run "Would restore SSL certificates for user $username" && return

    # TODO: edit to cover certs/ keys/ 
    log "Restoring SSL certificates for user $username"
    # apache_tls/ dir has LE certs, custom are in ssl/
    if [ -d "$real_backup_files_path/ssl" ]; then
        dest_dir="/home/$username/docker-data/volumes/${username}_html_data/_data/"
        for cert_file in "$real_backup_files_path/ssl"/*.crt; do
            local domain=$(basename "$cert_file" .crt)
            local key_file="$real_backup_files_path/ssl/$domain.key"
            local new_cert_file="$dest_dir/$domain.crt"
            local new_key_file="$dest_dir/$domain.key"
            if [ -f "$key_file" ]; then
                cp "$key_file" "$new_key_file"
                cp "$cert_file" "$new_cert_file"             
                log "Installing SSL certificate for domain: $domain"
                opencli domains-ssl "$domain" "/var/www/html/$domain.key" "/var/www/html/$domain.crt"
            else
                log "SSL key file not found for domain: $domain"
            fi
        done

        nohup docker --context=default exec caddy caddy reload --config /etc/caddy/Caddyfile > /dev/null 2>&1 &
        disown

    else
        log "No SSL certificates found to restore"
    fi
}

# ======================================================================
# DNS ZONES
restore_dns_zones() {
    log "Restoring DNS zones for user $cyberpanel_username"

    dry_run "Would restore DNS zones for user $cyberpanel_username" && return

    if [ -d "$real_backup_files_path/dnszones" ]; then
        for zone_file in "$real_backup_files_path/dnszones"/*; do
            local zone_name=$(basename "${zone_file%.db}")

            # Check if the destination zone file exists, if not, it was probably a subdomain that had no dns zone
            if [ ! -f "/etc/bind/zones/${zone_name}.zone" ]; then
                log "DNS zone file /etc/bind/zones/${zone_name}.zone does not exist. Skipping import for $zone_name."
                continue
            else
                log "Importing DNS zone: $zone_name"
            fi

            old_ip=$(grep -oP 'IP=\K[0-9.]+' ${real_backup_files_path}/cp/$cyberpanel_username)
            if [ -z "$old_ip" ]; then
                log "WARNING: old server ip address not detected in file ${real_backup_files_path}/cp/$cyberpanel_username - records will not be automatically updated to new ip address."
            else
                sed -i "s/$old_ip/$new_ip/g" $zone_file
            fi
            temp_file_of_original_zone=$(mktemp)
            temp_file_of_created_zone=$(mktemp)

            awk '/^@/ { found=1; last_line=NR } { if (found && NR > last_line) exit } { print }' "$zone_file" > "$temp_file_of_original_zone"
            awk '/NS/ { found=1; next } found { print }' "/etc/bind/zones/${zone_name}.zone" > "$temp_file_of_created_zone"
            cat "$temp_file_of_created_zone" >> "$temp_file_of_original_zone"
            mv "$temp_file_of_original_zone" "/etc/bind/zones/${zone_name}.zone"
            rm "$temp_file_of_created_zone"

            opencli domains-update_ns ${zone_name} >/dev/null 2>&1
            log "DNS zone file for $zone_name has been imported."
        done
    else
        log "No DNS zones found to restore"
    fi
}

create_home_mountpoint() {
    dry_run "Would create a symlink from html_data volume to /home/$cyberpanel_username/" && return
    
sed -i '/^[[:space:]]*volumes:[[:space:]]*$/{
  N
  /- html_data:\/var\/www\/html\// s|$|\n      - html_data:/home/${CONTEXT}/|
}' /home/$cyberpanel_username/docker-compose.yml

}

# ======================================================================
# HOME DIR
restore_files() {
    dry_run "Would restore files from /home/$cyberpanel_username/public_html/ to html_data volume" && return

    du_needed_for_home=$(du -sh "$real_backup_files_path/public_html" | cut -f1)
    log "Restoring home directory ($du_needed_for_home) to html_data volume"
    mkdir -p /home/$cyberpanel_username/docker-data/volumes/${cpanel_username}_html_data/
    rm -rf "$real_backup_files_path"/public_html/{.cpanel,.trash,wordpress-backups}
    mv $real_backup_files_path/public_html /home/$cyberpanel_username/docker-data/volumes/${cpanel_username}_html_data/_data
}

# ======================================================================
# PERMISSIONS
fix_perms(){
    local verbose="" #-v
    log "Changing permissions for all files and folders in user home directory /home/$cyberpanel_username/"

    dry_run "Would change permissions with command: find /home/$cyberpanel_username -print0 | xargs -0 chown $verbose $cyberpanel_username:$cyberpanel_username" && return
    
    if ! timeout 600 find /home/$cyberpanel_username -print0 | xargs -0 chown $verbose $cyberpanel_username:$cyberpanel_username > /dev/null 2>&1; then
        if [ $? -eq 124 ]; then
            log "ERROR: Timeout reached while changing permissions (10 minutes)."
        else
            log "ERROR: Failed to change permissions."
        fi
            log "       Make sure to change permissions manually from terminal with: find /home/$cyberpanel_username -print0 | xargs -0 chown -v $cyberpanel_username:$cyberpanel_username"
    fi
    
}

# ======================================================================
# WORDPRESS SITES
restore_wordpress() {
    dry_run "Would restore WordPress sites for user $cyberpanel_username" && return

    log "Checking user files for WordPress installations to add to Site Manager interface.."
    output=$(opencli websites-scan $cyberpanel_username)
        while IFS= read -r line; do
            log "$line"
        done <<< "$output"    
}

# ======================================================================
# DOMAINS
restore_domains() {
    if [ -f "$real_backup_files_path/userdata/main" ]; then
        file_path="$real_backup_files_path/userdata/main"



        log "Detected a total of $domains_total_count domains for user."

        current_domain_count=0

        create_domain(){
            domain="$1"
            type="$2"

            current_domain_count=$((current_domain_count + 1))
            if [[ $domain == \*.* ]]; then
                log "WARNING: Skipping wildcard domain $domain"
            else
                log "Restoring $type $domain (${current_domain_count}/${domains_total_count})"

                userdata_file="$real_backup_files_path/userdata/$domain"
                docroot=""
                if [ -f "$userdata_file" ]; then
                    original_docroot=$(awk -F': ' '/^documentroot:/ {print $2}' "$userdata_file" | xargs)
                    docroot="${original_docroot#/home/$cyberpanel_username/}"
                    docroot="/var/www/html/$docroot"
                else
                    log "WARNING: userdata file not found for $domain. Using default docroot."
                fi

                dry_run "Would restore $type $domain with --docroot ${docroot:-N/A}" && return
                          
                if opencli domains-whoowns "$domain" | grep -q "not found in the database."; then
                    if [ -n "$docroot" ]; then
                        output=$(opencli domains-add "$domain" "$cyberpanel_username" --docroot "$docroot" 2>&1)
                        while IFS= read -r line; do
                            log "$line"
                        done <<< "$output"
                    else
                        output=$(opencli domains-add "$domain" "$cyberpanel_username" 2>&1)
                        while IFS= read -r line; do
                            log "$line"
                        done <<< "$output"                        
                    fi
                else
                    log "WARNING: $type $domain already exists and will not be added to this user."
                fi
            fi

        }

        log "Processing main (primary) domain.."
        create_domain "$main_domain" "main domain"

        if [ "$parked_domains_count" -eq 0 ]; then
            log "No parked (alias) domains detected."
        else
            log "Processing parked (alias) domains.."
            for parked in "${parked_domains_array[@]}"; do
                create_domain "$parked" "alias domain"
            done
        fi

        if [ "$addon_domains_count" -eq 0 ]; then
            log "No addon domains detected."
        else
            log "Processing addon domains.."
            for addon in "${addon_domains_array[@]}"; do
                create_domain "$addon" "addon domain"
            done
        fi

        if [ "$filtered_sub_domains_count" -eq 0 ]; then
            log "No subdomains detected."
        else
            log "Processing sub-domains.."
            for filtered_sub in "${filtered_sub_domains[@]}"; do
                create_domain "$filtered_sub" "subdomain"
            done
        fi

        log "Finished importing $domains_total_count domains"

    else
        log "FATAL ERROR: domains file userdata/main is missing in backup file."
        exit 1
    fi
}

# ======================================================================
# CRONJOB
restore_cron() {
    log "Restoring cron jobs for user $cyberpanel_username"
    
    dry_run "Would restore cron jobs for user $cyberpanel_username" && return

    if [ -f "$real_backup_files_path/cron/$cyberpanel_username" ]; then
        sed -i '1,2d' "$real_backup_files_path/cron/$cyberpanel_username"
        ofelia_cron_path="/home/${cpanel_username}/crons.ini"
        > "$ofelia_cron_path"

        job_index=1
        job_found=false
        while IFS= read -r cron_line; do
            [[ -z "$cron_line" || "$cron_line" =~ ^# ]] && continue

            job_found=true
            schedule="* $(echo "$cron_line" | awk '{print $1, $2, $3, $4, $5}')"
            command=$(echo "$cron_line" | cut -d' ' -f6-)

            if [[ "$command" == *mysql* || "$command" == *mariadb* ]]; then
                container_name="$mysql_type"
                comment_prefix=""
            elif [[ "$command" == *php* ]]; then
                container_name="php-fpm-$php_version"
                comment_prefix=""
            else
                container_name=""
                comment_prefix="# "
            fi

            {
                echo "${comment_prefix}[job-exec \"${cpanel_username}_job_$job_index\"]"
                echo "${comment_prefix}schedule = $schedule"
                if [[ -n "$container_name" ]]; then
                    echo "${comment_prefix}container = $container_name"
                fi
                echo "${comment_prefix}command = $command"
                echo
            } >> "$ofelia_cron_path"

            ((job_index++))
        done < "$real_backup_files_path/cron/$cyberpanel_username"

        if [ "$job_found" = true ]; then
            log "Converted crontab to Ofelia config at: $ofelia_cron_path"
            log "Starting Cron service"
            output=$(cd /home/$cyberpanel_username && docker --context=$cyberpanel_username compose up -d cron >/dev/null 2>&1)           
            while IFS= read -r line; do
                log "$line"
            done <<< "$output"
        else
            log "No cron jobs found in file, not starting cron service"
            rm -f "$ofelia_cron_path"
        fi

    else
        log "No cron jobs found to restore"
    fi
}

# ======================================================================
# POST-IMPORT HOOK
run_custom_post_hook() {
    if [ -n "$post_hook" ]; then
        if [ -x "$post_hook" ]; then
            log "Executing post-hook script.."
            "$post_hook" "$cyberpanel_username"
        else
            log "WARNING: Post-hook file '$post_hook' is not executable or not found."
            exit 1
        fi
    fi
}

create_tmp_dir_and_path() {
    backup_filename="${backup_filename%.*}"
    backup_dir=$(mktemp -d /tmp/cpanel_import_XXXXXX)
    log "Created temporary directory: $backup_dir"
    real_backup_files_path="${backup_dir}/${backup_filename%.*}"
}

success_message() {
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    hours=$(( elapsed / 3600 ))
    minutes=$(( (elapsed % 3600) / 60 ))
    seconds=$(( elapsed % 60 ))

    log "Elapsed time: ${hours}h ${minutes}m ${seconds}s"

    dry_run "import process for user $cyberpanel_username completed" && return

    log "SUCCESS: Import for user $cyberpanel_username completed successfully."

    nohup opencli sentinel --action=user_create --title="User account '$cyberpanel_username' imported from cPanel backup" --message="User account '$cyberpanel_username' has been successfully imported from backup file '$backup_filename'" >/dev/null 2>&1 &
	disown
}

log_paths_are() {
    log "Log file: $LOG_FILE"
    log "PID: $pid"
}

start_message() {
    echo -e "
------------------ STARTING CPANEL ACCOUNT IMPORT ------------------
--------------------------------------------------------------------

Currently supported features:

├─ DOMAINS:
│  ├─ Primary domain, Addons, Aliases and Subdomains
│  ├─ SSL certificates
│  ├─ Domains access logs (Apache domlogs)
│  └─ DNS zones
├─ WEBSITES:
│  └─ WordPress instalations from WP Toolkit & Softaculous 
├─ DATABASES:
│    ├─ Remote access to MySQL
│    └─ MySQL databases, users and grants
├─ PHP:
│    └─ Installed version from Cloudlinux PHP Selector
├─ FILES
├─ CRONS
└─ ACCOUNT
    ├─ Notification preferences
    ├─ cPanel account creation date
    └─ cPanel account password

***emails, ftp, nodejs/python, postgres are not yet supported***

--------------------------------------------------------------------
  if you experience any errors with this script, please report to
    https://github.com/stefanpejcic/cPanel-to-OpenPanel/issues
--------------------------------------------------------------------
"
}


# ======================================================================
# FTP
ftp_accounts_import() {

    if [ -f "$ftp_conf" ]; then
        log "WARNING: Importing PureFTPD accounts is not yet supported"
        # this is cpanel's format:
        : '
        #cat proftpdpasswd
        pejcic:$6$cv9wnxSLeD1VEk.U$dm84PcqygxOWqT/uyMjrICKUPFeAQwOimJ8frihDCxjRfa1BKf6bnHIhWrbfmLrLn2YBSMnNatW09ZZMAS7GT/:1030:1034:pejcic:/home/pejcic:/bin/bash
        neko@pcx3.com:$6$7GZJXVYlO53hV.M7$750UVg6zKmX.Uj8cmWUxkRnNXxjuZfcm6BxnJceiFD5Zl80sB7jZL0UeHIpw2a3aQRWh.BMH9WuCPdqwj8zxG.:1030:1034:pejcic:/home/pejcic/folder:/bin/ftpsh
        whmcsmybekap@openpanel.co:$6$rDNAW7GZEAJ6zHJm$wYqg.H6USldSPCNz4jbgEi55tJ8hgeDzQCAmhSHfAPyzkJeP1u9E.LaLflQ.7kUbuRtBED7I70.QoCNRlxzEy0:1030:1034:pejcic:/home/pejcic/WHMC_MY_OPENPANEL_DB_BEKAP:/bin/ftpsh
        pejcic_logs:$6$cv9wnxSLeD1VEk.U$dm84PcqygxOWqT/uyMjrICKUPFeAQwOimJ8frihDCxjRfa1BKf6bnHIhWrbfmLrLn2YBSMnNatW09ZZMAS7GT/:1030:1034:pejcic:/etc/apache2/logs/domlogs/pejcic:/bin/ftpsh
        '
    fi
}

# ======================================================================
# EMAILS
import_email_accounts_and_data() {
        log "WARNING: Importing Email accounts is not yet supported"

        # TODO:
        # - check setting from openamdin where mails are stored
        # for each email check domain owner is the new user
        # mv email data to domain based dir
        # mv messages to domain based dir
        # list emails for user to confirm import
}


# ======================================================================

write_import_activity() {
    echo "$(date '+%Y-%m-%d %H:%M:%S')  $new_ip  Administrator ROOT user imported cpanel backup file" > /etc/openpanel/openpanel/core/users/$cyberpanel_username/activity.log
}



# MAIN
main() {
    start_message                                                              # what will be imported
    log_paths_are                                                              # where will we store the progress
    
    # STEP 1. PRE-RUN CHECKS
    check_if_valid_cp_backup "$backup_location"                                # is it?
    check_if_disk_available                                                    # calculate du needed for extraction
    validate_plan_exists                                                       # check if provided plan exists
    install_dependencies                                                       # install commands we will use for this script
    get_server_ipv4                                                            # used in mysql grants
    
    # STEP 2. EXTRACT
    create_tmp_dir_and_path                                                    # create /tmp/.. dir and set the path
    extract_cyberpanel_backup "$backup_location" "${backup_dir}"               # extract the archive
    check_if_user_exists                                                       # only after extract we have username!

    # STEP 3. IMPORT
    parse_metadata                                                             # get data and configurations
    restore_files                                                              # homedir
    create_new_user "$cyberpanel_username" "random" "$cyberpanel_email" "$plan_name"   # create user data and container
    setquota -u $cyberpanel_username 0 0 0 0 /                                     # set unlimited quota while we do import!
    create_home_mountpoint                                                     # mount /var/www/html/ to /home/USERNAME 
    get_mariadb_or_mysql_for_user                                              # mysql or mariadb
    fix_perms                                                                  # fix permissions for all files
    restore_php_version "$php_version"                                         # php v needs to run before domains 
    restore_domains                                                            # add domains
    restore_dns_zones                                                          # add dns 
    restore_mysql "$mysqldir"                                                  # mysql databases, users and grants
    restore_cron                                                               # cronjob
    restore_ssl "$cyberpanel_username"                                         # ssl certs
    restore_wordpress                                                          # import wp sites to sitemanager
    opencli user-quota $cyberpanel_username                                    # restore quota

    # STEP 4. IMPORT ENTERPRISE FEATURES
    import_email_accounts_and_data                                             # import emails, filters, forwarders..
    ftp_accounts_import                                                        # import ftp accounts
    
    reload_user_quotas                                                         # refresh du and inodes
    collect_stats                                                              # get cpu and ram usage
    write_import_activity

    # STEP 5. DELETE TMP FILES
    cleanup                                                                    # delete extracter files after import

    # STEP 6. NOTIFY USER
    success_message                                                            # have a 🍺

    # STEP 7. RUN ANY CUSTOM SCRIPTS
    run_custom_post_hook                                                       # any script to run after the import? example: edit dns on cp server, run tests, notify user, etc.
}

# ======================================================================
# ENTRYPOINT
define_data_and_log "$@"
