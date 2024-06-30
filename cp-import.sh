#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 [--backup-location <path> | --cpanel-username <username> --cpanel-password <password> --cpanel-host <host>] --plan-name <plan_name> --docker-image <image>"
    exit 1
}

# Function to check command success
check_success() {
    if [ $? -ne 0 ]; then
        echo "Error occurred in the previous command. Exiting."
        exit 1
    fi
}

# Function to install required packages
install_dependencies() {
    if [ -f /etc/debian_version ]; then
        sudo apt-get update
        check_success
        sudo apt-get install -y tar unzip jq mysql-client wget curl
        check_success
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y epel-release
        check_success
        sudo yum install -y tar unzip jq mysql wget curl
        check_success
    elif [ -f /etc/almalinux-release ]; then
        sudo dnf install -y tar unzip jq mysql wget curl
        check_success
    else
        echo "Unsupported OS. Please install tar, unzip, jq, mysql-client, wget, and curl manually."
        exit 1
    fi
}

# Function to download backup from cPanel
download_backup_from_cpanel() {
    local username="$1"
    local password="$2"
    local host="$3"
    local backup_dir="$4"

    # Command to generate and download backup from cPanel, using the UAPI
    local backup_path=$(curl -u "$username:$password" -k "https://$host:2083/execute/Backup/full_backup_to_homedir" | jq -r '.data')
    check_success
    wget --http-user=$username --http-password=$password "https://$host:2083/$backup_path" -O "$backup_dir/cpanel_backup.tar.gz"
    check_success
}

# Function to extract the backup file
extract_backup() {
    local backup_location="$1"
    local backup_dir="$2"
    mkdir -p "$backup_dir"
    check_success
    if [[ "$backup_location" == *.tar.gz ]]; then
        tar -xzf "$backup_location" -C "$backup_dir"
        check_success
    elif [[ "$backup_location" == *.zip ]]; then
        unzip "$backup_location" -d "$backup_dir"
        check_success
    else
        echo "Unsupported backup format. Only tar.gz and zip are supported."
        exit 1
    fi
}

# Function to parse cPanel backup metadata
parse_cpanel_metadata() {
    local backup_dir="$1"
    cpanel_username=$(grep -oP 'user: \K\S+' "$backup_dir"/userdata/main)
    cpanel_email=$(grep -oP 'email: \K\S+' "$backup_dir"/userdata/main)
    main_domain=$(grep -oP 'main_domain: \K\S+' "$backup_dir"/userdata/main)
    cpanel_password=$(grep -oP 'password: \K\S+' "$backup_dir"/shadow/"$cpanel_username")
    plan_name=$(grep -oP 'plan: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_disk=$(grep -oP 'disk_limit: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_bandwidth=$(grep -oP 'bandwidth_limit: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_domains=$(grep -oP 'max_domains: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_websites=$(grep -oP 'max_addon_domains: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_databases=$(grep -oP 'max_sql_db: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_inodes=$(grep -oP 'max_inodes: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_cpu=$(grep -oP 'max_cpu: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_ram=$(grep -oP 'max_ram: \K\S+' "$backup_dir"/metadata/account.yaml)
    plan_portspeed=$(grep -oP 'max_portspeed: \K\S+' "$backup_dir"/metadata/account.yaml)
    php_version=$(grep -oP 'php_version: \K\S+' "$backup_dir"/userdata/main)
    suspended=$(grep -oP 'suspended: \K\S+' "$backup_dir"/metadata/account.yaml)
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

    # Check if the plan already exists
    local existing_plan=$(opencli plan-list --json | jq -r ".[] | select(.name == \"$plan_name\") | .id")
    if [ -z "$existing_plan" ]; then
        opencli plan-create "$plan_name" "$plan_description" "$plan_domains" "$plan_websites" \
                             "$plan_disk" "$plan_inodes" "$plan_databases" "$plan_cpu" "$plan_ram" \
                             "$docker_image" "$plan_portspeed"
        check_success
    else
        echo "Plan $plan_name already exists, using the existing plan."
    fi
}

# Function to create or get user
create_or_get_user() {
    local username="$1"
    local password="$2"
    local email="$3"
    local plan_name="$4"

    local existing_user=$(opencli user-list --json | jq -r ".[] | select(.username == \"$username\") | .id")
    if [ -z "$existing_user" ]; then
        opencli user-add "$username" "$password" "$email" "$plan_name"
        check_success
    fi
}

# Function to restore PHP version
restore_php_version() {
    local username="$1"
    local php_version="$2"

    local current_version=$(opencli php-default_php_version "$username")
    if [ "$current_version" != "$php_version" ]; then
        local installed_versions=$(opencli php-enabled_php_versions "$username")
        if ! echo "$installed_versions" | grep -q "$php_version"; then
            opencli php-install_php_version "$username" "$php_version"
            check_success
        fi
        opencli php-enabled_php_versions --update "$username" "$php_version"
        check_success
    fi
}

# Function to restore domains
restore_domains() {
    local username="$1"
    local domain="$2"
    local path="/home/$username/$domain"

    local domain_owner=$(opencli domains-whoowns "$domain")
    if [ -z "$domain_owner" ]; then
        opencli domains-add "$domain" "$username" "$path"
        check_success
    fi
}

# Function to restore MySQL databases and users
restore_mysql() {
    local username="$1"
    local password="$2"
    local backup_dir="$3"

    if [ -d "$backup_dir/mysql" ]; then
        for db_file in "$backup_dir/mysql"/*.sql; do
            local db_name=$(basename "$db_file" .sql)
            openpanel db create "$db_name" "$username" "$password"
            check_success
            mysql -u "$username" -p"$password" "$db_name" < "$db_file"
            check_success
        done
    fi
}

# Function to restore SSL certificates
restore_ssl() {
    local username="$1"
    local backup_dir="$2"

    if [ -d "$backup_dir/ssl" ]; then
        for cert_file in "$backup_dir/ssl"/*.crt; do
            local domain=$(basename "$cert_file" .crt)
            local key_file="$backup_dir/ssl/$domain.key"
            openpanel ssl install --domain "$domain" --cert "$cert_file" --key "$key_file"
            check_success
        done
    fi
}

# Function to restore SSH access
restore_ssh() {
    local username="$1"
    local backup_dir="$2"

    local shell_access=$(grep -oP 'shell: \K\S+' "$backup_dir"/userdata/main)
    if [ "$shell_access" == "/bin/bash" ]; then
        opencli user-ssh enable "$username"
        check_success
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

    if [ -d "$backup_dir/dnszones" ]; then
        for zone_file in "$backup_dir/dnszones"/*; do
            local zone_name=$(basename "$zone_file")
            opencli dns-import-zone "$zone_file"
            check_success
        done
    fi
}

# Function to restore files
restore_files() {
    local backup_dir="$1"
    local username="$2"
    local domain="$3"
    cp -r "$backup_dir/homedir" "/home/$username/$domain/"
    check_success
    opencli files-fix_permissions "$username" "/home/$username/$domain"
    check_success
}

# Function to restore WordPress sites
restore_wordpress() {
    local backup_dir="$1"
    local username="$2"
    if [ -d "$backup_dir/wptoolkit" ]; then
        for wp_file in "$backup_dir/wptoolkit"/*.json; do
            opencli wp-import "$username" "$wp_file"
            check_success
        done
    fi
}

# Function to restore cron jobs
restore_cron() {
    local backup_dir="$1"
    local username="$2"
    if [ -f "$backup_dir/cron/crontab" ]; then
        crontab -u "$username" "$backup_dir/cron/crontab"
        check_success
    fi
}

# Parsing named parameters
backup_location=""
cpanel_username=""
cpanel_password=""
cpanel_host=""
plan_name=""
docker_image=""

while [ "$1" != "" ]; do
    case $1 in
        --backup-location ) shift
                            backup_location=$1
                            ;;
        --cpanel-username ) shift
                            cpanel_username=$1
                            ;;
        --cpanel-password ) shift
                            cpanel_password=$1
                            ;;
        --cpanel-host )     shift
                            cpanel_host=$1
                            ;;
        --plan-name )       shift
                            plan_name=$1
                            ;;
        --docker-image )    shift
                            docker_image=$1
                            ;;
        * )                 usage
                            exit 1
    esac
    shift
done

########### STEP 1. RUN CHECKS

# Ensure all necessary parameters are provided
if ([ -z "$backup_location" ] && ([ -z "$cpanel_username" ] || [ -z "$cpanel_password" ] || [ -z "$cpanel_host" ])) || [ -z "$plan_name" ] || [ -z "$docker_image" ]; then
    usage
fi

# Ensure the script is run with superuser privileges
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi

# Install required packages
install_dependencies

########### STEP 2. EXTRACT

# Determine backup source and process accordingly
backup_dir="/tmp/backup_extract"
if [ ! -z "$backup_location" ]; then
    # Local backup path provided
    extract_backup "$backup_location" "$backup_dir"
elif [ ! -z "$cpanel_username" ] && [ ! -z "$cpanel_password" ] && [ ! -z "$cpanel_host" ]; then
    # Remote cPanel credentials provided
    download_backup_from_cpanel "$cpanel_username" "$cpanel_password" "$cpanel_host" "$backup_dir"
    backup_location="$backup_dir/cpanel_backup.tar.gz"
    extract_backup "$backup_location" "$backup_dir"
fi

########### STEP 3. START IMPORT

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
if [ -d "$backup_dir/homedir/public_html" ]; then
    restore_website "$main_domain" "$backup_dir/homedir/public_html"
fi

# Restore addon domains
if [ -d "$backup_dir/userdata" ]; then
    for domain_file in "$backup_dir/userdata"/*.yaml; do
        domain=$(basename "$domain_file" .yaml)
        domain_path=$(grep -oP 'documentroot: \K\S+' "$domain_file")
        restore_website "$domain" "$domain_path"
    done
fi

# Restore subdomains
if [ -d "$backup_dir/userdata" ]; then
    for subdomain_file in "$backup_dir/userdata"/*_subdomains.yaml; do
        subdomain=$(basename "$subdomain_file" _subdomains.yaml)
        subdomain_path=$(grep -oP 'documentroot: \K\S+' "$subdomain_file")
        full_subdomain="$subdomain.$main_domain"
        restore_website "$full_subdomain" "$subdomain_path"
    done
fi

# Restore MySQL databases and users
restore_mysql "$cpanel_username" "$cpanel_password" "$backup_dir"

# Restore Emails
if [ -d "$backup_dir/mail" ]; then
    cp -r "$backup_dir/mail" "/home/$cpanel_username/mail"
    check_success
    opencli files-fix_permissions "$cpanel_username" "/home/$cpanel_username/mail"
    check_success
fi

# Restore SSL certificates
restore_ssl "$cpanel_username" "$backup_dir"

# Restore SSH access
restore_ssh "$cpanel_username" "$backup_dir"

# Restore DNS zones
restore_dns_zones "$cpanel_username" "$backup_dir"

# Restore Files
restore_files "$backup_dir" "$cpanel_username" "$main_domain"

# Restore WordPress sites
restore_wordpress "$backup_dir" "$cpanel_username"

# Restore Cron jobs
restore_cron "$backup_dir" "$cpanel_username"

# Suspend user if needed
if [ "$suspended" == "1" ]; then
    opencli user-suspend "$cpanel_username"
    check_success
fi

# Fix file permissions for the entire home directory
opencli files-fix_permissions "$cpanel_username" "/home/$cpanel_username"

########### STEP 4. CLEANUP

# Cleanup
rm -rf "$backup_dir"

echo "Restore completed successfully."
