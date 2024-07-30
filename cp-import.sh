#!/bin/bash

script_dir=$(dirname "$0")

set -eo pipefail

# root user is needed
if [[ $EUID -ne 0 ]]; then
    log "This script must be run as root or with sudo privileges"
    exit 1
fi


###############################################################
# HELPER FUNCTIONS

usage() {
    echo "Usage: $0 --backup-location <path> --plan-name <plan_name>"
    echo ""
    echo "Example: $0 --backup-location /home/backup-7.29.2024_13-22-32_stefan.tar.gz  --plan-name default_plan_nginx"
    exit 1
}

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

handle_error() {
    log "Error occurred in function '$1' on line $2"
    exit 1
}


trap 'handle_error "${FUNCNAME[-1]}" "$LINENO"' ERR

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_dependencies() {
    log "Checking dependencies..."
	
	install_needed=false
	
	# needed commands
	declare -A commands=(
	    ["tar"]="tar"
	    ["unzip"]="unzip"
	    ["jq"]="jq"
	    ["mysql"]="mysql-client"
	    ["wget"]="wget"
	    ["curl"]="curl"
	)
	
	for cmd in "${!commands[@]}"; do
	    if ! command_exists "$cmd"; then
	        install_needed=true
	        break
	    fi
	done


	# If installation is needed, update package list and install missing packages
	if [ "$install_needed" = true ]; then
 	    log "Updating package manager.."
	    apt-get update
	    for cmd in "${!commands[@]}"; do
	        if ! command_exists "$cmd"; then
	 		log "Installing ${commands[$cmd]}"
	            apt-get install -y "${commands[$cmd]}"
	        fi
	    done
     	    log "Dependencies installed successfully."
	fi
}


get_server_ipv4(){

	# Get server ipv4 from ip.openpanel.co or ifconfig.me
	new_ip=$(curl --silent --max-time 2 -4 https://ip.openpanel.co || wget --timeout=2 -qO- https://ip.openpanel.co || curl --silent --max-time 2 -4 https://ifconfig.me)
	
	# if no internet, get the ipv4 from the hostname -I
	if [ -z "$new_ip" ]; then
	    new_ip=$(ip addr|grep 'inet '|grep global|head -n1|awk '{print $2}'|cut -f1 -d/)
	fi

}


validate_plan_exists(){
    check_plan_sql=$(mysql -Dpanel -se "SELECT COUNT(*) FROM plans WHERE name = '$plan_name';")
    
    # Check the result
    if [ "$check_plan_sql" -gt 0 ]; then
        log "Plan name '$plan_name' exists in the plans table."
    else
        log "Plan name '$plan_name' does not exist in the plans table."
        exit 1
    fi
}


###############################################################













###############################################################
# MAIN FUNCTIONS

check_if_valid_cp_backup(){
    local backup_location="$1"

    ARCHIVE_SIZE=$(stat -c%s "$backup_location")

    # Identify the backup type
    local backup_filename=$(basename "$backup_location")
    extraction_command=""

    case "$backup_filename" in
        cpmove-*.tar.gz)
            log "Identified cpmove backup"
            extraction_command="tar -xzf"
            EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 2))
	    ;;
        backup-*.tar.gz)
            log "Identified full or partial cPanel backup"
            extraction_command="tar -xzf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 3))
            ;;
        *.tar.gz)
            log "Identified gzipped tar backup"
            extraction_command="tar -xzf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 3))
            ;;
        *.tgz)
            log "Identified tgz backup"
            extraction_command="tar -xzf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 3))
            ;;
        *.tar)
            log "Identified tar backup"
            extraction_command="tar -xf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 2))
            ;;
        *.zip)
            log "Identified zip backup"
            extraction_command="unzip"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 2))
            ;;
        *)
            log "Unrecognized backup format: $backup_filename"
            exit 1
            ;;
    esac
}


check_if_disk_available(){

#idealy should run after creating user

TMP_DIR="/tmp"
HOME_DIR="/home"

# Get available space in /tmp and home directories in bytes
AVAILABLE_TMP=$(df --output=avail "$TMP_DIR" | tail -n 1)
AVAILABLE_HOME=$(df --output=avail "$HOME_DIR" | tail -n 1)

AVAILABLE_TMP=$(($AVAILABLE_TMP * 1024))
AVAILABLE_HOME=$(($AVAILABLE_HOME * 1024))

# Check if there's enough space
if [[ $AVAILABLE_TMP -ge $EXTRACTED_SIZE && $AVAILABLE_HOME -ge $EXTRACTED_SIZE ]]; then
    lig "There is enough disk space to extract the archive and copy it to the home directory."
else
    log "FATAL ERROR: Not enough disk space."
    if [[ $AVAILABLE_TMP -lt $EXTRACTED_SIZE ]]; then
        log "Insufficient space in /tmp."
    fi
    if [[ $AVAILABLE_HOME -lt $EXTRACTED_SIZE ]]; then
        log "Insufficient space in the /home directory."
    fi
    exit 1
fi

}



# Extract
extract_cpanel_backup() {
    backup_location="$1"
    backup_dir="$2"
    log "Extracting backup from $backup_location to $backup_dir"
    mkdir -p "$backup_dir"


    #TODO: check if server has enough space to unpack it and then to copy.
    # should be free on /home about 80% of the compressed archive and 80% on tmp.
    # in case tmp is toosmall, use /home  but then at least 160% of archive needs to be available.

    # Extract the backup
    if [ "$extraction_command" = "unzip" ]; then
        $extraction_command "$backup_location" -d "$backup_dir"
    else
        $extraction_command "$backup_location" -C "$backup_dir"
    fi
    if [ $? -eq 0 ]; then
    	log "Backup extracted successfully."
    else
    	log "Backup extraction failed."
        #TODO: do cleanup!
	exit 1
    fi

    # Handle nested archives (common in some cPanel backups)
    for nested_archive in "$backup_dir"/*.tar.gz "$backup_dir"/*.tgz; do
        if [ -f "$nested_archive" ]; then
            log "Found nested archive: $nested_archive"
            tar -xzf "$nested_archive" -C "$backup_dir"
            rm "$nested_archive"  # Remove the nested archive after extraction
        fi
    done

    # debug only!
    #log "Contents of extracted backup:"
    #find "$backup_dir" -type f | sed 's/^/  /'
}



# Function to locate important directories in the extracted backup
locate_backup_directories() {
    log "Locating important files in the extracted backup"

    # Try to locate the key directories
    homedir=$(find "$backup_dir" -type d -name "homedir" | head -n 1)
    if [ -z "$homedir" ]; then
        homedir=$(find "$backup_dir" -type d -name "public_html" -printf '%h\n' | head -n 1)
    fi
    if [ -z "$homedir" ]; then
        log "FATAL ERROR: Unable to locate home directory in the backup"
        exit 1
    fi

    mysqldir=$(find "$backup_dir" -type d -name "mysql" | head -n 1)
    if [ -z "$mysqldir" ]; then
        log "WARNING: Unable to locate MySQL directory in the backup"
        #exit 1 #not critical
    fi

    mysql_conf=$(find "$backup_dir" -type f -name "mysql.sql-auth.json" | head -n 1)
    if [ -z "$mysqldir" ]; then
        log "WARNING: Unable to locate MySQL grants file in the backup"
        #exit 1 #not critical
    fi

    cp_file=$(find "$backup_dir" -type f -path "*/cp/*" -name "$cpanel_username" | head -n 1)
    if [ -z "$cp_file" ]; then
        log "FATAL ERROR: Unable to locate cp/$cpanel_username file in the backup"
        exit 1
    fi

    log "Backup directories located successfully"
    log "Home directory: $homedir"
    log "MySQL directory: $mysqldir"
    log "MySQL grants: $mysql_conf"
    log "cPanel configuration: $cp_file"
}



# Function to parse cPanel backup metadata
parse_cpanel_metadata() {
    log "Parsing cPanel metadata..."

    local metadata_file="$real_backup_files_path/userdata/main"
    if [ ! -f "$metadata_file" ]; then
        metadata_file="$real_backup_files_path/meta/user.yaml"
    fi
    
    main_domain=$(grep -oP 'main_domain: \K\S+' "$metadata_file" | tr -d '\r')

    php_version=$(grep -oP 'phpversion:\s*\K\S+' ${real_backup_files_path}/userdata/${main_domain})
    
    cpanel_email=$(grep -oP 'CONTACTEMAIL=\K\S+' ${real_backup_files_path}/cp/${cpanel_username})
    if [ -z "$cpanel_email" ]; then
    	cpanel_email=" " #set blank
    fi

    
    log "cPanel metadata parsed successfully."
    log "Email: $cpanel_email"
    log "Main Domain: $main_domain"
    log "PHP Version: $php_version"

}


check_if_user_exists(){  
    backup_filename=$(basename "$backup_location")
    cpanel_username="${backup_filename##*_}"
    cpanel_username="${cpanel_username%%.*}"
    log "Username: $cpanel_username"
    
    local existing_user=""
    if opencli user-list --json > /dev/null 2>&1; then
        existing_user=$(opencli user-list --json | jq -r ".[] | select(.username == \"$cpanel_username\") | .id")
    fi
    if [ -z "$existing_user" ]; then
        log "Username $cpanel_username is available, staring import.."
    else
        log "FATAL ERROR: $cpanel_username already exists."
        exit 1
    fi

}

# Function to create or get user
create_new_user() {
    local username="$1"
    local password="$2"
    local email="$3"
    local plan_name="$4"

	create_user_command=$(opencli user-add "$username" "$password" "$email" "$plan_name" 2>&1)
 
	if echo "$create_user_command" | grep -q "Successfully added user"; then
	    log "User $$username successfully created."
	else
	    log "FATAL ERROR: User addition failed. Response did not contain the expected success message."
	    log "Command output: $create_user_command"
	    exit 1
	fi
}

# Function to restore PHP version
restore_php_version() {
    local username="$1"
    local php_version="$2"

	  # Check if php_version is "inherit"
	  if [ "$php_version" == "inherit" ]; then
	    log "PHP version is set to inherit. No changes will be made."
	  else
	    log "Restoring PHP version $php_version for user $username"
	    local current_version=$(opencli php-default_php_version "$username")
	    if [ "$current_version" != "$php_version" ]; then
	        local installed_versions=$(opencli php-enabled_php_versions "$username")
	        if ! echo "$installed_versions" | grep -q "$php_version"; then
	            opencli php-install_php_version "$username" "$php_version"
	        fi
	        opencli php-enabled_php_versions --update "$username" "$php_version"
	    fi
	  fi
}

# Function to restore domains
restore_domains() {
    local username="$1"
    local domain="$2"
    local path="$3"

    log "Restoring domain $domain for user $username"

	if opencli domains-whoowns "$domain" | grep -q "not found in the database."; then
	    log "Restoring domain $domain for user $username"
	    ## TODO FOR STEFAN ## opencli domains-add "$domain" "$username"
     	    log "Added domain $domain" # fake until then..
	else
	    log "WARNING: Domain $domain already exists and will not be added to this user."
	fi





    
}

# Function to restore MySQL databases and users
restore_mysql() {
    local mysql_dir="$1"
    
    log "Restoring MySQL databases for user $cpanel_username"
    
	#https://jira.mariadb.org/browse/MDEV-34183
 	apply_sandbox_workaround() {
	    local db_file="$1"
	    text_to_check='enable the sandbox mode'
	    local first_line
	
	    first_line=$(head -n 1 ${real_backup_files_path}/mysql/$db_file)
     		if echo "$first_line" | grep -q "$text_to_check"; then
	        log "WARNING: Database dump was created on a MariaDB server with '--sandbox' mode. Applying workaround for backwards compatibility to MySQL (BUG: https://jira.mariadb.org/browse/MDEV-34183)"
	        # Remove the first line and save the changes to the same file
	        tail -n +2 "${real_backup_files_path}/mysql/$db_file" > "${real_backup_files_path}/mysql/${db_file}.workaround" && mv "${real_backup_files_path}/mysql/${db_file}.workaround" "${real_backup_files_path}/mysql/$db_file"
	    fi
	}    


    if [ -d "$mysql_dir" ]; then

         # STEP 1. get old server ip and replace it in the mysql.sql file that has import permissions
        old_ip=$(grep -oP 'IP=\K[0-9.]+' ${real_backup_files_path}/cp/$cpanel_username)
        log "Replacing old server IP: $old_ip with new IP: $new_ip in database grants"  
        sed -i "s/$old_ip/$new_ip/g" $mysql_conf

        # STEP 2. start mysql for user
            log "Initializing MySQL service for user"
            docker exec $cpanel_username bash -c "service mysql start >/dev/null 2>&1"

        # STEP 3. create and import databases
        for db_file in "$mysql_dir"/*.create; do
            local db_name=$(basename "$db_file" .create)
	   
            log "Creating database: $db_name"           
	    apply_sandbox_workaround "$db_name.create" # Apply the workaround if it's needed
	    docker cp ${real_backup_files_path}/mysql/$db_name.create $cpanel_username:/tmp/${db_name}.create  >/dev/null 2>&1
            docker exec $cpanel_username bash -c "mysql < /tmp/${db_name}.create"

            log "Restoring database: $db_name"
	    apply_sandbox_workaround "$db_name.sql" # Apply the workaround if it's needed
            docker cp ${real_backup_files_path}/mysql/$db_name.sql $cpanel_username:/tmp/$db_name.sql >/dev/null 2>&1     
            docker exec $cpanel_username bash -c "mysql ${db_name} < /tmp/${db_name}.sql"
        done
        
        # STEP 4. import grants 
            log "Importing database grants"
	    python3 $script_dir/mysql/json_2_sql.py ${real_backup_files_path}/mysql.sql-auth.json ${real_backup_files_path}/mysql.sql-auth.sql
     
            docker cp ${real_backup_files_path}/mysql.sql-auth.sql $cpanel_username:/tmp/mysql.sql-auth.sql   >/dev/null 2>&1
            docker exec $cpanel_username bash -c "mysql < /tmp/mysql.sql-auth.sql"

        # STEP 5. flush privilegies
    else
        log "No MySQL databases found to restore"
    fi
}

# Function to restore SSL certificates
restore_ssl() {
    local username="$1"

    log "Restoring SSL certificates for user $username"
    if [ -d "$real_backup_files_path/ssl" ]; then
        for cert_file in "$real_backup_files_path/ssl"/*.crt; do
            local domain=$(basename "$cert_file" .crt)
            local key_file="$real_backup_files_path/ssl/$domain.key"
            if [ -f "$key_file" ]; then
                log "Installing SSL certificate for domain: $domain"
                opencli ssl install --domain "$domain" --cert "$cert_file" --key "$key_file"
            else
                log "SSL key file not found for domain: $domain"
            fi
        done
    else
        log "No SSL certificates found to restore"
    fi
}

# Function to restore SSH access
restore_ssh() {
    local username="$1"

    log "Restoring SSH access for user $username"
    local shell_access=$(grep -oP 'shell: \K\S+' "$real_backup_files_path/userdata/main")
    if [ "$shell_access" == "/bin/bash" ]; then
        opencli user-ssh enable "$username"
        if [ -f "$real_backup_files_path/.ssh/id_rsa.pub" ]; then
            mkdir -p "/home/$username/.ssh"
            cp "$real_backup_files_path/.ssh/id_rsa.pub" "/home/$username/.ssh/authorized_keys"
            chown -R "$username:$username" "/home/$username/.ssh"
        fi
    fi
}

# Function to restore DNS zones
restore_dns_zones() {

    log "Restoring DNS zones for user $cpanel_username"
    if [ -d "$real_backup_files_path/dnszones" ]; then
        for zone_file in "$real_backup_files_path/dnszones"/*; do
            local zone_name=$(basename "$zone_file")
            log "Importing DNS zone: $zone_name"
            opencli dns-import-zone "$zone_file"
        done
    else
        log "No DNS zones found to restore"
    fi
}

# Function to restore files
restore_files() {
    local backup_dir="$1"
    local username="$2"

    log "Restoring files for user $username to /home/$username/"
    cp -r "$backup_dir/homedir" "/home/$username/"  #TODO: use parallel or xargs
    docker exec $username bash -c "chown -R 1000:34 /home/$username"
}

# Function to restore WordPress sites
restore_wordpress() {
    local backup_dir="$1"
    local username="$2"

    log "Restoring WordPress sites for user $username"
    if [ -d "$backup_dir/wptoolkit" ]; then
        for wp_file in "$backup_dir/wptoolkit"/*.json; do
            log "Importing WordPress site from: $wp_file"
            opencli wp-import "$username" "$wp_file"
        done
    else
        log "No WordPress data found to restore"
    fi
}

# Function to restore cron jobs
restore_cron() {
    local backup_dir="$1"
    local username="$2"

    log "Restoring cron jobs for user $username"
    if [ -f "$backup_dir/cron/$username" ]; then
        crontab -u "$username" "$backup_dir/cron/crontab"
        docker cp $backup_dir/cron/$username $username:/var/spool/cron/crontabs/$username
        docker exec $username bash -c "service cron restart"

        # TODO: start cron service for user
        #docker exec $username sed CRON_STATUS="on" /etc/entrypoint.sh'

    else
        log "No cron jobs found to restore"
    fi
}

###############################################################











convert_cpanel_password (){

#TODO:
# get hash and salt from shadow file in extracted files
# covert to scrypt hass
#replace stored scrypt hash in db for that user
#
echo "nothing yet.."

}




# Main execution
main() {
    local backup_location=""
    local plan_name=""

    # Parse command-line arguments
    while [ "$1" != "" ]; do
        case $1 in
            --backup-location ) shift
                                backup_location=$1
                                ;;
            --plan-name )       shift
                                plan_name=$1
                                ;;
            * )                 usage
        esac
        shift
    done

    # Validate required parameters
    if [ -z "$backup_location" ] || [ -z "$plan_name" ]; then
        usage
    fi


    ################# PRE-RUN CHECKS
    check_if_valid_cp_backup "$backup_location"
    check_if_disk_available
    check_if_user_exists
    validate_plan_exists
    install_dependencies
    get_server_ipv4 #used in myhsql grants

    # Create a unique temporary directory
    backup_dir=$(mktemp -d /tmp/cpanel_import_XXXXXX)
    log "Created temporary directory: $backup_dir"

         ## RUN PROCESS



    
    # Extract backup
    extract_cpanel_backup "$backup_location" "$backup_dir"

	# backup extracted files
    real_backup_files_path=$(find "$backup_dir" -type f -name "version" | head -n 1 | xargs dirname)
    log "Extracted backup folder: $real_backup_files_path"
    
    # Locate important directories
    locate_backup_directories

    # Parse cPanel metadata
    parse_cpanel_metadata  #TODO: extract single file and get data from it!

    # Create user
    cpanel_password="repalcedinnextfunc"
    create_new_user "$cpanel_username" "$cpanel_password" "$cpanel_email" "$plan_name"

# Set password
    convert_cpanel_password   #TODO: convert hash from cp


    # Restore PHP version
    restore_php_version "$cpanel_username" "$php_version"

    # Restore Domains and Websites
    restore_website() {
        local domain="$1"
        local path="$2"
        restore_domains "$cpanel_username" "$domain" "$path"
    }

    # Restore main domain 	#THIS currently runs 2x
    #if [ -d "$homedir/public_html" ]; then
    #    restore_website "$main_domain" "$homedir/public_html"
    #fi

    # Restore addon domains and subdomains
    if [ -d "$backup_dir/userdata" ]; then
        for domain_file in "$backup_dir/userdata"/*.yaml; do
            domain=$(basename "$domain_file" .yaml)
            domain_path=$(grep -oP 'documentroot: \K\S+' "$domain_file")
            restore_website "$domain" "$domain_path"
        done

        for subdomain_file in "$backup_dir/userdata"/*_subdomains.yaml; do
            subdomain=$(basename "$subdomain_file" _subdomains.yaml)
            subdomain_path=$(grep -oP 'documentroot: \K\S+' "$subdomain_file")
            full_subdomain="$subdomain.$main_domain"
            restore_website "$full_subdomain" "$subdomain_path"
        done
    fi

    # Restore other components
    restore_mysql "$mysqldir"
    restore_ssl "$cpanel_username"
    restore_ssh "$cpanel_username"
    restore_dns_zones
    restore_files "$backup_dir" "$cpanel_username"
    restore_wordpress "$backup_dir" "$cpanel_username"
    restore_cron "$backup_dir" "$cpanel_username"

    # Fix file permissions for the entire home directory
    log "Fixing file permissions for user $cpanel_username"
    opencli files-fix_permissions "$cpanel_username" "/home/$cpanel_username"

    # Cleanup
    log "Cleaning up temporary files"
    rm -rf "$backup_dir"

    log "Restore completed successfully."
}

         ## POST-RUN CHECKS



###############################################################

# Run the main function
main "$@"
