#!/bin/bash

script_dir=$(dirname "$0")
timestamp="$(date +'%Y-%m-%d_%H-%M-%S')"



set -eo pipefail

###############################################################
# HELPER FUNCTIONS

usage() {
    echo "Usage: $0 --backup-location <path> --plan-name <plan_name>"
    echo ""
    echo "Example: $0 --backup-location /home/backup-7.29.2024_13-22-32_stefan.tar.gz  --plan-name default_plan_nginx"
    exit 1
}

log() {
	local message="$1"
	#output to user
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message"
	# save in log
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" >> "$log_file"
}


define_data_and_log(){
    local backup_location=""
    local plan_name=""

	# root user is needed
	if [[ $EUID -ne 0 ]]; then
	    log "This script must be run as root or with sudo privileges"
	    exit 1
	fi


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

	# Format log file
	base_name="$(basename "$backup_location")"
	base_name_no_ext="${base_name%.*}" 
 	local log_dir="/var/log/openpanel/admin/imports"
  	mkdir -p $log_dir
	log_file="$log_dir/${base_name_no_ext}_${timestamp}.log"

# Run the main function
main 

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
	    ["parallel"]="parallel"
	    ["rsync"]="rsync"
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
	    apt-get update  >/dev/null 2>&1
	    for cmd in "${!commands[@]}"; do
	        if ! command_exists "$cmd"; then
	 		log "Installing ${commands[$cmd]}"
	            apt-get install -y "${commands[$cmd]}"  >/dev/null 2>&1
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
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 2))
            ;;
        *.tar.gz)
            log "Identified gzipped tar backup"
            extraction_command="tar -xzf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 2))
            ;;
        *.tgz)
            log "Identified tgz backup"
            extraction_command="tar -xzf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 3))
            ;;
        *.tar)
            log "Identified tar backup"
            extraction_command="tar -xf"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 3))
            ;;
        *.zip)
            log "Identified zip backup"
            extraction_command="unzip"
	    EXTRACTED_SIZE=$(($ARCHIVE_SIZE * 3))
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
    log "There is enough disk space to extract the archive and copy it to the home directory."
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
    local email="$3"
    local plan_name="$4"

	create_user_command=$(opencli user-add "$cpanel_username" generate "$email" "$plan_name" 2>&1)
			 while IFS= read -r line; do
		    		log "$line"
			done <<< "$create_user_command"
   
	if echo "$create_user_command" | grep -q "Successfully added user"; then
	    :
	else
	    log "FATAL ERROR: User addition failed. Response did not contain the expected success message."
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


# Function to restore MySQL databases and users
restore_mysql() {
    local mysql_dir="$1"
    local sandbox_warning_logged=false
    
    log "Restoring MySQL databases for user $cpanel_username"
    
	#https://jira.mariadb.org/browse/MDEV-34183
 	apply_sandbox_workaround() {
	    local db_file="$1"
	    text_to_check='enable the sandbox mode'
	    local first_line
	
	    first_line=$(head -n 1 ${real_backup_files_path}/mysql/$db_file)
     		if echo "$first_line" | grep -q "$text_to_check"; then
       			 if [ "$sandbox_warning_logged" = false ]; then
			        log "WARNING: Database dumps were created on a MariaDB server with '--sandbox' mode. Applying workaround for backwards compatibility to MySQL (BUG: https://jira.mariadb.org/browse/MDEV-34183)"
	   			sandbox_warning_logged=true
			 fi
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
	    docker exec "$cpanel_username" sed -i 's/CRON_STATUS="off"/CRON_STATUS="on"/' /etc/entrypoint.sh
	
	# STEP 3. create and import databases
 	total_databases=$(ls "$mysql_dir"/*.create | wc -l)
	log "Starting import for $total_databases MySQL databases"
	if [ "$total_databases" -gt 0 ]; then
	current_db=1
	        for db_file in "$mysql_dir"/*.create; do
	            local db_name=$(basename "$db_file" .create)
	   
	            log "Creating database: $db_name (${current_db}/${total_databases})"           
		    apply_sandbox_workaround "$db_name.create" # Apply the workaround if it's needed
		    docker cp ${real_backup_files_path}/mysql/$db_name.create $cpanel_username:/tmp/${db_name}.create  >/dev/null 2>&1
	            docker exec $cpanel_username bash -c "mysql < /tmp/${db_name}.create"
	
	            log "Importing tables for database: $db_name"
		    apply_sandbox_workaround "$db_name.sql" # Apply the workaround if it's needed
	            docker cp ${real_backup_files_path}/mysql/$db_name.sql $cpanel_username:/tmp/$db_name.sql >/dev/null 2>&1     
	            docker exec $cpanel_username bash -c "mysql ${db_name} < /tmp/${db_name}.sql"
		    current_db=$((current_db + 1))
	        done
	 log "Finished processing $current_db databases"
	 else
	    log "WARNING: No MySQL databases found"
	fi
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
            ###opencli dns-import-zone "$zone_file"
        done
    else
        log "No DNS zones found to restore"
    fi
}

# Function to restore files
restore_files() {
    du_needed_for_home=$(du -sh "$real_backup_files_path/homedir" | cut -f1)
    log "Restoring files ($du_needed_for_home/) to /home/$cpanel_username/"

    #log "DEBUG: $real_backup_files_path/homedir du before:"
    #du -sh "$real_backup_files_path/homedir"
    
    #log "DEBUG: /home/$cpanel_username/ su before:"
    #du -sh "/home/$cpanel_username/"

	rsync -av --progress "$real_backup_files_path/homedir" "/home/$cpanel_username/" 2>&1 | while IFS= read -r line; do
	  log "$line"
	done
    #TODO: use parallel or xargs
    
    #output=$(cp -r "$real_backup_files_path/homedir" "/home/$cpanel_username/" 2>&1)
    #	while IFS= read -r line; do
    #   log "$line"
    # done <<< "$output"


	log "Finished transferring files, comparing to source.."
	original_size=$(du -sb "$real_backup_files_path/homedir" | cut -f1)
	copied_size=$(du -sb "/home/$cpanel_username/" | cut -f1)
	
	if [[ "$original_size" -eq "$copied_size" ]]; then
	  log "The original and target directories have the same size."
	else
	  log "WARNING: The original and target directories differ in size after restore."
	  log "Original size: $original_size bytes"
	  log "Target size:   $copied_size bytes"
	fi
	

    #log "DEBUG: $real_backup_files_path/homedir du after:"
    #du -sh "$real_backup_files_path/homedir"
    
    #log "DEBUG: /home/$cpanel_username/ su after:"
    #du -sh "/home/$cpanel_username/"

    
    docker exec $cpanel_username bash -c "chown -R 1000:33 /home/$cpanel_username"
}

# Function to restore WordPress sites
restore_wordpress() {
    local real_backup_files_path="$1"
    local username="$2"

    log "Restoring WordPress sites for user $username"
    if [ -d "$real_backup_files_path/wptoolkit" ]; then
        for wp_file in "$real_backup_files_path/wptoolkit"/*.json; do
            log "Importing WordPress site from: $wp_file"
            opencli wp-import "$username" "$wp_file"
        done
    else
        log "No WordPress data found to restore"
    fi
}


restore_domains(){
    # Restore addon domains and subdomains
    if [ -d "$real_backup_files_path/userdata" ]; then

	files=($(find "$real_backup_files_path/userdata" -type f ! -name "*.json" ! -name "*?SSL" ! -name "*.db" ! -name "main"))
        domains_total_count=${#files[@]}
        current_domain_count=0

	# main domain		 	
 	if [ -d "$homedir/public_html" ]; then
	   	current_domain_count=$((current_domain_count + 1))
	    	domains_total_count=$((domains_total_count + 1))

		if opencli domains-whoowns "$main_domain" | grep -q "not found in the database."; then
		    log "Restoring main domain: $main_domain (${current_domain_count}/${domains_total_count})"
      			output=$(opencli domains-add "$main_domain" "$cpanel_username" 2>&1)
			 while IFS= read -r line; do
		    		log "$line"
			done <<< "$output"
		else
		    log "WARNING: Primary domain $main_domain already exists and will not be added to this user."
		fi
   	fi


 	# addons
	for domain_file in "${files[@]}"; do
	    domain=$(basename "$domain_file")
	    #domain_path=$(grep -oP 'documentroot: \K\S+' "$domain_file")
     	    current_domain_count=$((current_domain_count + 1))
	    log "Restoring domain: $domain (${current_domain_count}/${domains_total_count})"
     
		if opencli domains-whoowns "$domain" | grep -q "not found in the database."; then
		    log "Restoring addon domain $domain (${current_domain_count}/${domains_total_count})"
      			output=$(opencli domains-add "$domain" "$cpanel_username" 2>&1)
			 while IFS= read -r line; do
		    		log "$line"
			done <<< "$output"     
		else
		    log "WARNING: Addon domain $domain already exists and will not be added to this user."
		fi    
	done
	log "Finished importing $current_domain_count domains"
    fi
}


# Function to restore cron jobs
restore_cron() {

    log "Restoring cron jobs for user $cpanel_username"
    if [ -f "$real_backup_files_path/cron/$cpanel_username" ]; then
    
 			# exclude shell and email variables from file!
    			sed -i '1,2d' "$real_backup_files_path/cron/$cpanel_username"

      			output=$(docker cp $real_backup_files_path/cron/$cpanel_username $cpanel_username:/var/spool/cron/crontabs/$cpanel_username 2>&1)
			 while IFS= read -r line; do
		    		log "$line"
			done <<< "$output"
   
      			output=$(docker exec $cpanel_username bash -c "crontab -u $cpanel_username /var/spool/cron/crontabs/$cpanel_username" 2>&1)
			 while IFS= read -r line; do
		    		log "$line"
			done <<< "$output"

      			output=$(docker exec $cpanel_username bash -c "service cron restart" 2>&1)
			 while IFS= read -r line; do
		    		log "$line"
			done <<< "$output"

 
	docker exec "$cpanel_username" sed -i 's/CRON_STATUS="off"/CRON_STATUS="on"/' /etc/entrypoint.sh  >/dev/null 2>&1

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

log "Log file: $log_file"

    # PRE-RUN CHECKS
    check_if_valid_cp_backup "$backup_location"
    check_if_disk_available
    check_if_user_exists
    validate_plan_exists
    install_dependencies
    get_server_ipv4 #used in myhsql grants

    # unique
    backup_dir=$(mktemp -d /tmp/cpanel_import_XXXXXX)
    log "Created temporary directory: $backup_dir"
   
    # extract
    extract_cpanel_backup "$backup_location" "$backup_dir"
    real_backup_files_path=$(find "$backup_dir" -type f -name "version" | head -n 1 | xargs dirname)
    log "Extracted backup folder: $real_backup_files_path"
    
    # locate important directories
    locate_backup_directories
    parse_cpanel_metadata

    # create new user
    create_new_user "$cpanel_username" "random" "$cpanel_email" "$plan_name"
    #convert_cpanel_password   #TODO: convert hash from cp

    # restore data
    restore_domains
    restore_files
    restore_mysql "$mysqldir"
    restore_cron
    restore_php_version "$cpanel_username" "$php_version"
    restore_ssl "$cpanel_username"
    restore_ssh "$cpanel_username"
    restore_dns_zones  #TODO
    restore_wordpress "$real_backup_files_path" "$cpanel_username" #TO REMOVE
    

    log "Fixing file permissions for user $cpanel_username" #TODO
    opencli files-fix_permissions "$cpanel_username" "/home/$cpanel_username" #TODO

    # Cleanup
    log "Cleaning up temporary files"
    rm -rf "$backup_dir"

    log "SUCCESS: Import for user $cpanel_username completed successfully."

}


###############################################################

# MAIN FUNCTION
define_data_and_log "$@"
