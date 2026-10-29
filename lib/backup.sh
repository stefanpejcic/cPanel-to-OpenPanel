# shellcheck shell=bash
# cp-import.sh step: checking, extracting and reading the cPanel backup, sourced by cp-import.sh

# ======================================================================
# CHECK BACKUP FILE EXTENSION AND DETERMINE SIZE NEEDED FOR RESTORE
check_if_valid_cp_backup() {
    local backup_location="$1"
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
# DECOMPRESS GZIPPED ARCHIVES ONCE, REUSED FOR BOTH VALIDATION AND EXTRACTION
# (avoids paying the gzip decompression cost twice on large backups)
prepare_extraction_source() {
    local backup_location="$1"

    if [ "$extraction_command" = "tar -xzf" ]; then
        raw_tar_file="${backup_dir}/.raw_extract.tar"
        log "Decompressing archive once to reuse for validation and extraction"
        if ! pigz -dc -- "$backup_location" > "$raw_tar_file" 2>>"$LOG_FILE"; then
            log "FATAL ERROR: Failed to decompress backup archive."
            cleanup
            exit 1
        fi
        extraction_source="$raw_tar_file"
    else
        raw_tar_file=""
        extraction_source="$backup_location"
    fi
}

# ======================================================================
# VALIDATE ARCHIVE ENTRIES DO NOT ESCAPE THE EXTRACTION DIRECTORY (ZIP SLIP)
validate_archive_paths() {
    local entries
    local entry

    if [ "$extraction_command" = "unzip" ]; then
        entries=$(unzip -Z1 -- "$extraction_source" 2>>"$LOG_FILE")
    else
        entries=$(tar -tf "$extraction_source" 2>>"$LOG_FILE")
    fi

    if [ -z "$entries" ]; then
        log "FATAL ERROR: Unable to list archive contents for validation."
        cleanup
        exit 1
    fi

    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        if [[ "$entry" == /* ]]; then
            log "FATAL ERROR: Unsafe absolute path in archive entry: $entry"
            log "Aborting import - this backup may be malicious (Zip Slip)."
            cleanup
            exit 1
        fi
        IFS='/' read -ra path_parts <<< "$entry"
        for part in "${path_parts[@]}"; do
            if [ "$part" = ".." ]; then
                log "FATAL ERROR: Unsafe path traversal detected in archive entry: $entry"
                log "Aborting import - this backup may be malicious (Zip Slip)."
                cleanup
                exit 1
            fi
        done
    done <<< "$entries"
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
extract_cpanel_backup() {
    backup_location="$1"
    backup_dir="$2"
    backup_dir="${backup_dir%.*}"
    log "Extracting backup from $backup_location to $backup_dir"
    mkdir -p "$backup_dir"

    if [ "$extraction_command" = "unzip" ]; then
        unzip "$extraction_source" -d "$backup_dir"
    else
        backup_size=$(stat -c %s "${extraction_source}")
		zero_one_percent=$((backup_size / 1000000))
		[ "$zero_one_percent" -le 0 ] && zero_one_percent=1
		tar --checkpoint="$zero_one_percent" --checkpoint-action=dot -xf "$extraction_source" -C "$backup_dir" 2>>"$LOG_FILE"
    fi

    if [ $? -eq 0 ]; then
        log "Backup extracted successfully."
        log "Extracted backup folder: $real_backup_files_path"
        [ -n "$raw_tar_file" ] && rm -f "$raw_tar_file"
    else
        log "FATAL ERROR: Backup extraction failed."
        cleanup
        exit 1
    fi
}

# ======================================================================
# LOCATE FILES IN EXTRACTED BACKUP
locate_backup_directories() {
    log "Locating important files in the extracted backup"

    homedir=$(find "$backup_dir" -type d -name "homedir" | head -n 1)
    if [ -z "$homedir" ]; then
        homedir=$(find "$backup_dir" -type d -name "public_html" -printf '%h\n' | head -n 1)
    fi
	[[ -n $homedir ]] || { log "FATAL ERROR: Unable to locate home directory in the backup"; exit 1; }

    mysqldir="$real_backup_files_path/mysql"
	[[ -d $mysqldir ]] || log "WARNING: Unable to locate MySQL directory in the backup"

    mysql_conf="$real_backup_files_path/mysql.sql"
	[[ -f $mysql_conf ]] || log "WARNING: Unable to locate MySQL grants file in the backup"

    psqldir="$real_backup_files_path/psql"
    psql_grants="$real_backup_files_path/psql_grants.sql"
    psql_users="$real_backup_files_path/psql_users.sql"
    ftp_conf="$real_backup_files_path/proftpdpasswd"

    domain_logs="$real_backup_files_path/logs/"
	[[ -d $domain_logs ]] || log "WARNING: Unable to locate apache domlogs in the backup"

    cp_file="$real_backup_files_path/cp/$cpanel_username"
	[[ -f $cp_file ]] || { log "FATAL ERROR: Unable to locate cp/$cpanel_username file in the backup"; exit 1; }

    log "Backup directories and configuration files located:"
    log "- Home directory:       $homedir"
    log "- MySQL directory:      $mysqldir"
    log "- MySQL grants:         $mysql_conf"
    [[ -d $psqldir ]] && log "- PostgreSQL directory: $psqldir"
	[[ -f $psql_grants ]] && log "- PostgreSQL grants:    $psql_grants"
	[[ -f $psql_users ]] && log "- PostgreSQL users:     $psql_users"
	[[ -f $ftp_conf ]] && log "- PureFTPD users:       $ftp_conf"
    log "- Domain logs:          $domain_logs"
    log "- cPanel configuration: $cp_file"
}

# ======================================================================
# PARSE CPANEL BACKUP METADATA FOR ACCOUNT AND SERVICE INFORMATION
parse_cpanel_metadata() {
    log "Starting to parse cPanel metadata..."

    cp_file="${real_backup_files_path}/cp/${cpanel_username}"

    if [ ! -f "$cp_file" ]; then
        log "WARNING: cp file $cp_file not found. Using default values."
        main_domain=""
        cpanel_email=""
        php_version="inherit"
    else

        get_cp_value() {
            local key="$1"
            local default="$2"
            local value
            value=$(grep "^$key=" "$cp_file" | cut -d'=' -f2-)
            if [ -z "$value" ]; then
                echo "$default"
            else
                echo "$value"
            fi
        }

		# TODO: reuse for webhook_url in openpanel
        PUSHBULLET_ACCESS_TOKEN=$(get_cp_value "PUSHBULLET_ACCESS_TOKEN" "")

        main_domain=$(get_cp_value "DNS" "")
        cpanel_email=$(get_cp_value "CONTACTEMAIL" "")
        [ -z "$cpanel_email" ] && cpanel_email=$(get_cp_value "CONTACTEMAIL2" "")
        [ -z "$cpanel_email" ] && cpanel_email=$(get_cp_value "EMAIL" "")

        # Cloudlinux PHP Selector
        cfg_file="${real_backup_files_path}/homedir/.cl.selector/defaults.cfg"
        if [ -f "$cfg_file" ]; then
            php_version=$(grep '^php\s*=' "$cfg_file" | awk -F '=' '{print $2}' | tr -d '[:space:]')
            [ -z "$php_version" ] && php_version="inherit"
        else
            php_version="inherit"
        fi

        ip_address=$(get_cp_value "IP" "")
        plan=$(get_cp_value "PLAN" "default")
        max_addon=$(get_cp_value "MAXADDON" "0")
        max_ftp=$(get_cp_value "MAXFTP" "unlimited")
        max_sql=$(get_cp_value "MAXSQL" "unlimited")
        max_pop=$(get_cp_value "MAXPOP" "unlimited")
        max_sub=$(get_cp_value "MAXSUB" "unlimited")

        log "Additional metadata parsed:"
        log "IP Address:           $ip_address"
        log "Plan:                 $plan"
        log "Max Addon Domains:    $max_addon"
        log "Max FTP Accounts:     $max_ftp"
        log "Max SQL Databases:    $max_sql"
        log "Max Email Accounts:   $max_pop"
        log "Max Subdomains:       $max_sub"
    fi

    main_domain="${main_domain:-}"
    cpanel_email="${cpanel_email:-admin@$main_domain}"
    php_version="${php_version:-inherit}"

    log "Email:                ${cpanel_email:-Not found}"
    log "PHP Version:          $php_version"
    log "Finished parsing cPanel metadata."
}

create_tmp_dir_and_path() {
    backup_filename="${backup_filename%.*}"
    backup_dir=$(mktemp -d /tmp/cpanel_import_XXXXXX)
    log "Created temporary directory: $backup_dir"
    real_backup_files_path="${backup_dir}/${backup_filename%.*}"
}
