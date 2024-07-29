#!/bin/bash

set -eo pipefail

# Function to display usage
usage() {
    echo "Usage: $0 --backup-location <path> --plan-name <plan_name> --docker-image <image>"
    exit 1
}

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to handle errors
handle_error() {
    log "Error occurred in function '$1' on line $2"
    exit 1
}

trap 'handle_error "${FUNCNAME[-1]}" "$LINENO"' ERR

# Function to install required packages
install_dependencies() {
    log "Installing dependencies..."
    if [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y tar unzip jq mysql-client wget curl
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y epel-release tar unzip jq mysql wget curl
    elif [ -f /etc/almalinux-release ]; then
        sudo dnf install -y tar unzip jq mysql wget curl
    else
        log "Unsupported OS. Please install tar, unzip, jq, mysql-client, wget, and curl manually."
        exit 1
    fi
    log "Dependencies installed successfully."
}

# Function to identify and extract the cPanel backup
extract_cpanel_backup() {
    local backup_location="$1"
    local backup_dir="$2"
    log "Identifying and extracting backup from $backup_location to $backup_dir"
    mkdir -p "$backup_dir"

    # Identify the backup type
    local backup_filename=$(basename "$backup_location")
    local extraction_command=""

    case "$backup_filename" in
        cpmove-*.tar.gz)
            log "Identified cpmove backup"
            extraction_command="tar -xzf"
            ;;
        backup-*.tar.gz)
            log "Identified full or partial cPanel backup"
            extraction_command="tar -xzf"
            ;;
        *.tar.gz)
            log "Identified gzipped tar backup"
            extraction_command="tar -xzf"
            ;;
        *.tgz)
            log "Identified tgz backup"
            extraction_command="tar -xzf"
            ;;
        *.tar)
            log "Identified tar backup"
            extraction_command="tar -xf"
            ;;
        *.zip)
            log "Identified zip backup"
            extraction_command="unzip"
            ;;
        *)
            log "Unrecognized backup format: $backup_filename"
            exit 1
            ;;
    esac

    # Extract the backup
    if [ "$extraction_command" = "unzip" ]; then
        $extraction_command "$backup_location" -d "$backup_dir"
    else
        $extraction_command "$backup_location" -C "$backup_dir"
    fi

    log "Backup extracted successfully."

    # Handle nested archives (common in some cPanel backups)
    for nested_archive in "$backup_dir"/*.tar.gz "$backup_dir"/*.tgz; do
        if [ -f "$nested_archive" ]; then
            log "Found nested archive: $nested_archive"
            tar -xzf "$nested_archive" -C "$backup_dir"
            rm "$nested_archive"  # Remove the nested archive after extraction
        fi
    done

    # List contents of extracted backup for debugging
    log "Contents of extracted backup:"
    find "$backup_dir" -type f | sed 's/^/  /'
}

# Function to locate important directories in the extracted backup
locate_backup_directories() {
    local backup_dir="$1"
    log "Locating important directories in the extracted backup"

    # Try to locate the key directories
    homedir=$(find "$backup_dir" -type d -name "public_html" -printf '%h\n' | head -n 1)
    if [ -z "$homedir" ]; then
        log "Unable to locate home directory in the backup"
        exit 1
    fi

    mysqldir=$(find "$backup_dir" -type d -name "mysql" | head -n 1)
    if [ -z "$mysqldir" ]; then
        log "Unable to locate MySQL directory in the backup"
        exit 1
    fi

    log "Backup directories located successfully"
    log "Home directory: $homedir"
    log "MySQL directory: $mysqldir"
}

# Function to parse cPanel backup metadata
parse_cpanel_metadata() {
    local backup_dir="$1"
    log "Parsing cPanel metadata..."

    # Try different possible locations for metadata
    local metadata_file=""
    for possible_file in "$backup_dir/userdata/main" "$backup_dir/user.metadata" "$homedir/../.cpanel/userdata/main" "$backup_dir/*/userdata/main"; do
        if [ -f "$possible_file" ]; then
            metadata_file="$possible_file"
            break
        fi
    done

    if [ -z "$metadata_file" ]; then
        log "Unable to locate metadata file. Prompting for manual input."
        read -p "Enter cPanel username: " cpanel_username
        read -p "Enter cPanel email: " cpanel_email
        read -p "Enter main domain: " main_domain
        read -p "Enter PHP version: " php_version
    else
        log "Metadata file found: $metadata_file"
        cpanel_username=$(grep -oP 'user: \K\S+' "$metadata_file")
        cpanel_email=$(grep -oP 'email: \K\S+' "$metadata_file")
        main_domain=$(grep -oP 'main_domain: \K\S+' "$metadata_file")
        php_version=$(grep -oP 'php_version: \K\S+' "$metadata_file")
    fi

    # Parse account limits
    local account_file="$backup_dir/metadata/account.yaml"
    if [ -f "$account_file" ]; then
        log "Account metadata file found: $account_file"
        plan_name=$(grep -oP 'plan: \K\S+' "$account_file")
        plan_disk=$(grep -oP 'disk_limit: \K\S+' "$account_file")
        plan_bandwidth=$(grep -oP 'bandwidth_limit: \K\S+' "$account_file")
        plan_domains=$(grep -oP 'max_domains: \K\S+' "$account_file")
        plan_websites=$(grep -oP 'max_addon_domains: \K\S+' "$account_file")
        plan_databases=$(grep -oP 'max_sql_db: \K\S+' "$account_file")
        plan_inodes=$(grep -oP 'max_inodes: \K\S+' "$account_file")
        plan_cpu=$(grep -oP 'max_cpu: \K\S+' "$account_file")
        plan_ram=$(grep -oP 'max_ram: \K\S+' "$account_file")
        plan_portspeed=$(grep -oP 'max_portspeed: \K\S+' "$account_file")
        suspended=$(grep -oP 'suspended: \K\S+' "$account_file")
    else
        log "Account metadata file not found. Using default values."
        plan_name="default"
        plan_disk="unlimited"
        plan_bandwidth="unlimited"
        plan_domains="unlimited"
        plan_websites="unlimited"
        plan_databases="unlimited"
        plan_inodes="unlimited"
        plan_cpu="100"
        plan_ram="1024"
        plan_portspeed="100"
        suspended="0"
    fi

    log "cPanel metadata parsed successfully."
    log "Username: $cpanel_username"
    log "Email: $cpanel_email"
    log "Main Domain: $main_domain"
    log "PHP Version: $php_version"
    log "Plan Name: $plan_name"
}

# Function to create or check and get an existing plan
create_or_get_plan() {
    local plan_name="$1"
    local plan_description="$2"
    local plan_domains="$3"
    local plan_websites="$4"
    local plan_disk="$5"
    local plan_inodes="$6"
    local plan_databases="$7"
    local plan_cpu="$8"
    local plan_ram="$9"
    local docker_image="${10}"
    local plan_portspeed="${11}"

    log "Creating or getting plan: $plan_name"
    local existing_plan=$(opencli plan-list --json | jq -r ".[] | select(.name == \"$plan_name\") | .id")
    if [ -z "$existing_plan" ]; then
        opencli plan-create "$plan_name" "$plan_description" "$plan_domains" "$plan_websites" \
                             "$plan_disk" "$plan_inodes" "$plan_databases" "$plan_cpu" "$plan_ram" \
                             "$docker_image" "$plan_portspeed"
    else
        log "Plan $plan_name already exists, using the existing plan."
    fi
}

# Function to create or get user
create_or_get_user() {
    local username="$1"
    local password="$2"
    local email="$3"
    local plan_name="$4"

    log "Creating or getting user: $username"
    local existing_user=$(opencli user-list --json | jq -r ".[] | select(.username == \"$username\") | .id")
    if [ -z "$existing_user" ]; then
        opencli user-add "$username" "$password" "$email" "$plan_name"
    else
        log "User $username already exists."
    fi
}

# Function to restore PHP version
restore_php_version() {
    local username="$1"
    local php_version="$2"

    log "Restoring PHP version $php_version for user $username"
    local current_version=$(opencli php-default_php_version "$username")
    if [ "$current_version" != "$php_version" ]; then
        local installed_versions=$(opencli php-enabled_php_versions "$username")
        if ! echo "$installed_versions" | grep -q "$php_version"; then
            opencli php-install_php_version "$username" "$php_version"
        fi
        opencli php-enabled_php_versions --update "$username" "$php_version"
    fi
}

# Function to restore domains
restore_domains() {
    local username="$1"
    local domain="$2"
    local path="$3"

    log "Restoring domain $domain for user $username"
    local domain_owner=$(opencli domains-whoowns "$domain")
    if [ -z "$domain_owner" ]; then
        opencli domains-add "$domain" "$username" "$path"
    else
        log "Domain $domain already exists and is owned by $domain_owner"
    fi
}

# Function to restore MySQL databases and users
restore_mysql() {
    local username="$1"
    local password="$2"
    local mysql_dir="$3"

    log "Restoring MySQL databases for user $username"
    if [ -d "$mysql_dir" ]; then
        for db_file in "$mysql_dir"/*.sql; do
            local db_name=$(basename "$db_file" .sql)
            log "Restoring database: $db_name"
            opencli db create "$db_name" "$username" "$password"
            mysql -u "$username" -p"$password" "$db_name" < "$db_file"
        done
    else
        log "No MySQL databases found to restore"
    fi
}

# Function to restore emails
restore_emails() {
    local username="$1"
    local backup_dir="$2"

    log "Restoring emails for user $username"
    if [ -d "$backup_dir/mail" ]; then
        cp -r "$backup_dir/mail" "/home/$username/mail"
        opencli files-fix_permissions "$username" "/home/$username/mail"
    else
        log "No email data found to restore"
    fi
}

# Function to restore SSL certificates
restore_ssl() {
    local username="$1"
    local backup_dir="$2"

    log "Restoring SSL certificates for user $username"
    if [ -d "$backup_dir/ssl" ]; then
        for cert_file in "$backup_dir/ssl"/*.crt; do
            local domain=$(basename "$cert_file" .crt)
            local key_file="$backup_dir/ssl/$domain.key"
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
    local backup_dir="$2"

    log "Restoring SSH access for user $username"
    local shell_access=$(grep -oP 'shell: \K\S+' "$backup_dir/userdata/main")
    if [ "$shell_access" == "/bin/bash" ]; then
        opencli user-ssh enable "$username"
        if [ -f "$backup_dir/.ssh/id_rsa.pub" ]; then
            mkdir -p "/home/$username/.ssh"
            cp "$backup_dir/.ssh/id_rsa.pub" "/home/$username/.ssh/authorized_keys"
            chown -R "$username:$username" "/home/$username/.ssh"
        fi
    fi
}

# Function to restore DNS zones
restore_dns_zones() {
    local username="$1"
    local backup_dir="$2"

    log "Restoring DNS zones for user $username"
    if [ -d "$backup_dir/dnszones" ]; then
        for zone_file in "$backup_dir/dnszones"/*; do
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
    local domain="$3"

    log "Restoring files for user $username and domain $domain"
    cp -r "$backup_dir/homedir" "/home/$username/$domain/"
    opencli files-fix_permissions "$username" "/home/$username/$domain"
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
    if [ -f "$backup_dir/cron/crontab" ]; then
        crontab -u "$username" "$backup_dir/cron/crontab"
    else
        log "No cron jobs found to restore"
    fi
}

# Main execution
main() {
    local backup_location=""
    local plan_name=""
    local docker_image=""

    # Parse command-line arguments
    while [ "$1" != "" ]; do
        case $1 in
            --backup-location ) shift
                                backup_location=$1
                                ;;
            --plan-name )       shift
                                plan_name=$1
                                ;;
           --docker-image )    shift
                                docker_image=$1
                                ;;
            * )                 usage
        esac
        shift
    done

    # Validate required parameters
    if [ -z "$backup_location" ] || [ -z "$plan_name" ] || [ -z "$docker_image" ]; then
        usage
    fi

    # Ensure the script is run with superuser privileges
    if [[ $EUID -ne 0 ]]; then
        log "This script must be run as root or with sudo privileges"
        exit 1
    fi

    # Install required packages
    install_dependencies

    # Extract backup
    local backup_dir="/tmp/backup_extract"
    extract_cpanel_backup "$backup_location" "$backup_dir"

    # Locate important directories
    locate_backup_directories "$backup_dir"

    # Parse cPanel metadata
    parse_cpanel_metadata "$backup_dir"

    # Create or get hosting plan
    create_or_get_plan "$plan_name" "$plan_name plan" "$plan_domains" "$plan_websites" "$plan_disk" "$plan_inodes" "$plan_databases" "$plan_cpu" "$plan_ram" "$docker_image" "$plan_portspeed"

    # Create or get user
    create_or_get_user "$cpanel_username" "$cpanel_password" "$cpanel_email" "$plan_name"

    # Restore PHP version
    restore_php_version "$cpanel_username" "$php_version"

    # Restore Domains and Websites
    restore_website() {
        local domain="$1"
        local path="$2"
        restore_domains "$cpanel_username" "$domain" "$path"
    }

    # Restore main domain
    if [ -d "$homedir/public_html" ]; then
        restore_website "$main_domain" "$homedir/public_html"
    fi

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
    restore_mysql "$cpanel_username" "$cpanel_password" "$mysqldir"
    restore_emails "$cpanel_username" "$backup_dir"
    restore_ssl "$cpanel_username" "$backup_dir"
    restore_ssh "$cpanel_username" "$backup_dir"
    restore_dns_zones "$cpanel_username" "$backup_dir"
    restore_files "$backup_dir" "$cpanel_username" "$main_domain"
    restore_wordpress "$backup_dir" "$cpanel_username"
    restore_cron "$backup_dir" "$cpanel_username"

    # Suspend user if needed
    if [ "$suspended" == "1" ]; then
        log "Suspending user $cpanel_username as per backup metadata"
        opencli user-suspend "$cpanel_username"
    fi

    # Fix file permissions for the entire home directory
    log "Fixing file permissions for user $cpanel_username"
    opencli files-fix_permissions "$cpanel_username" "/home/$cpanel_username"

    # Cleanup
    log "Cleaning up temporary files"
    rm -rf "$backup_dir"

    log "Restore completed successfully."
}

# Run the main function
main "$@"
