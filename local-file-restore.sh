#!/bin/bash

: '
SUPPORTED 

- PLAN
read plan limits
check if plan already exists: opencli plan-list [--json]
create plan: opencli plan-create plan_name description domains_limit websites_limit disk_limit inodes_limit db_limit cpu ram docker_image bandwidth storage_file

- USER
check if username already exists, create user with: opencli user-add <USERNAME> <PASSWORD|generate> <EMAIL> <PLAN_NAME>


-DEDI IP
check if user had dedicated ip and set dedi ip on openpnael: opencli user-ip <USERNAME> <IP>

- PHP
detect php version from the backup file
check if it is installed and set as default in docker container: opencli php-default_php_version <username>
if not default, check if installed: opencli php-enabled_php_versions <username>
if not installed, install it: opencli php-install_php_version <username> <php_version>
and set as default: opencli php-enabled_php_versions --update <username>

TODO in future: read .ini files or Cloudlinux settings of version per domain and if multiple versions, install and set for each domain same version: opencli php-domain_php <domain_name> --update <new_php_version>



- DOMAINS
check if domain already exists on server: opencli domains-whoowns <DOMAIN-NAME>
if not, add domain: opencli domains-add <DOMAIN> <username> *(path will be /home/<username>/<DOMAIN>/)



- MYSQL
check if databases, then start mysql in container
create databases
create users
assing users
import dumps


- SSL
for each domain check validity and import if valid.
import ssl 
read force http option from cpanel and set it

- SSH
check if user has ssh key pair, if he does copy and authorize
enable ssh for that user: opencli user-ssh <check|enable|disable> <username>



- DNS
check if zone is valid
copy zone
change ns in zone
update serial in zone


- FILES
cp the files for each domain document root to adequate folder



- WORDPRESS
read wptoolkit/softaculous files and import the site in openpanel wpmanager


- CRONS
cp crontab file
enable cron service in docker container













FOR FUTURE

- NODEJS/PYTHON APPS FROM CPANEL APPLICATION MANAGER
if exist, check versions and conf: start file, .htacces proxy..
install pm2 and needed py/node & pip/npm
add in openpanel PM2 interface
start app

- GIT

- EMAILS

- IP BLOCKER

- MODSEC ON/OFF STATUS OF DOMAIN

- REDIRECTS

'























# Function to display usage
usage() {
    echo "Usage: $0 --backup-location <path> --docker-image <image>"
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
        # Debian-based system
        sudo apt-get update
        check_success
        sudo apt-get install -y tar unzip jq mysql-client
        check_success
    elif [ -f /etc/redhat-release ]; then
        # RedHat-based system
        sudo yum install -y epel-release
        check_success
        sudo yum install -y tar unzip jq mysql
        check_success
    elif [ -f /etc/almalinux-release ]; then
        # AlmaLinux system
        sudo dnf install -y tar unzip jq mysql
        check_success
    else
        echo "Unsupported OS. Please install tar, unzip, jq, and mysql-client manually."
        exit 1
    fi
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
}

# Parsing named parameters
while [ "$1" != "" ]; do
    case $1 in
        --backup-location ) shift
                            backup_location=$1
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
if [ -z "$backup_location" ] || [ -z "$docker_image" ]; then
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

#todo: check available du and if username is available

# Extract backup
backup_dir="/tmp/backup_extract"
extract_backup "$backup_location" "$backup_dir"





########### STEP 3. START IMPORT

# Parse cPanel metadata
parse_cpanel_metadata "$backup_dir"

# Restore User
openpanel user create "$cpanel_username" "$cpanel_email" user
check_success
echo -e "$cpanel_password\n$cpanel_password" | openpanel user set-password "$cpanel_username"
check_success

# Create and assign hosting plan
opencli plan-create "$plan_name" "$plan_name plan" "$plan_domains" "$plan_websites" "$plan_disk" "$plan_inodes" "$plan_databases" "$plan_cpu" "$plan_ram" "$docker_image" "$plan_portspeed"
check_success
openpanel user assign-plan "$cpanel_username" "$plan_name"
check_success

# Restore Domains and Websites
restore_website() {
    local domain="$1"
    local path="$2"
    openpanel domain add "$domain" "$cpanel_username"
    check_success
    openpanel site add "$domain" --path "$path" --docker-image "$docker_image"
    check_success
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

# Restore Databases and Users
if [ -d "$backup_dir/mysql" ]; then
    for db_file in "$backup_dir/mysql"/*.sql; do
        db_name=$(basename "$db_file" .sql)
        openpanel db create "$db_name" "$cpanel_username" "$cpanel_password"
        check_success
        mysql -u "$cpanel_username" -p"$cpanel_password" "$db_name" < "$db_file"
        check_success
    done
fi

# Restore Emails
if [ -d "$backup_dir/mail" ]; then
    cp -r "$backup_dir/mail" "/home/$cpanel_username/mail"
    check_success
    chown -R "$cpanel_username:$cpanel_username" "/home/$cpanel_username/mail"
    check_success
fi

# Restore SSL Certificates
if [ -d "$backup_dir/ssl" ]; then
    for cert_file in "$backup_dir/ssl"/*.crt; do
        domain=$(basename "$cert_file" .crt)
        key_file="$backup_dir/ssl/$domain.key"
        openpanel ssl install --domain "$domain" --cert "$cert_file" --key "$key_file"
        check_success
    done
# we can also try to generate free ssl for all domains owned by user with: opencli ssl-user <username>
    
fi

# Restore Cron Jobs
if [ -d "$backup_dir/cron" ]; then
    crontab -u "$cpanel_username" "$backup_dir/cron/crontab"
    check_success
fi

# Fix file permissions
chown -R "$cpanel_username:$cpanel_username" "/home/$cpanel_username"

# for in contianer we will use: opencli files-fix_permissions [USERNAME] [PATH]

########### STEP 4. CLEANUP

# Cleanup
rm -rf "$backup_dir"

echo "Restore completed successfully."
