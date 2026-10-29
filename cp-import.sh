#!/bin/bash
pid=$$
# absolute, the import cds into the user's home before it runs mysql/json_2_sql.py
script_dir=$(dirname "$(readlink -f "$0")")
timestamp="$(date +'%Y-%m-%d_%H-%M-%S')"
start_time=$(date +%s)
DEBUG=true

# each import step lives in its own file under lib/
# shellcheck source-path=SCRIPTDIR
. "$script_dir/lib/common.sh"
. "$script_dir/lib/backup.sh"
. "$script_dir/lib/account.sh"
. "$script_dir/lib/domains.sh"
. "$script_dir/lib/databases.sh"
. "$script_dir/lib/cron.sh"
. "$script_dir/lib/ftp.sh"
. "$script_dir/lib/mail.sh"


# ======================================================================
# START HELPER FUNCTIONS

usage() {
    echo "Usage: $0 --backup-location='<path>' --plan-name='<plan_name>' [--dry-run] [--reseller=<reseller>]"
    echo
    echo "Example: $0 --backup-location='/home/backup-7.29.2024_13-22-32_pejcic.tar.gz' --plan-name='Standard plan' --dry-run"
    exit 1
}


trap 'handle_error "${FUNCNAME[0]}" "$LINENO"' ERR


define_data_and_log(){
    local backup_location=""
    plan_name=""
    DRY_RUN=false

	strip_quotes() {
	    local str="$1"
	    str="${str%\"}"  # remove trailing double quote
	    str="${str#\"}"  # remove leading double quote
	    str="${str%\'}"  # remove trailing single quote
	    str="${str#\'}"  # remove leading single quote
	    echo "$str"
	}
	
	for arg in "$@"; do
	    case $arg in
	        --backup-location=*) backup_location=$(strip_quotes "${arg#*=}") ;;
	        --plan-name=*)       plan_name=$(strip_quotes "${arg#*=}") ;;
	        --post-hook=*)       post_hook=$(strip_quotes "${arg#*=}") ;;
			--reseller=*)        reseller=$(strip_quotes "${arg#*=}") ;;
	        --dry-run)           DRY_RUN=true ;;
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


# END HELPER FUNCTIONS
# ======================================================================


success_message() {
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    hours=$(( elapsed / 3600 ))
    minutes=$(( (elapsed % 3600) / 60 ))
    seconds=$(( elapsed % 60 ))

    log "Elapsed time: ${hours}h ${minutes}m ${seconds}s"

    dry_run "import process for user $cpanel_username completed" && return

    log "SUCCESS: Import for user $cpanel_username completed successfully."

    nohup opencli sentinel --action=user_create --title="User account '$cpanel_username' imported from cPanel backup" --message="User account '$cpanel_username' has been successfully imported from backup file '$backup_filename'" >/dev/null 2>&1 &
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
│  ├─ DNS zones
│  ├─ SSL certificates
│  ├─ Modsecurity status
│  └─ Access logs (Apache domlogs)
├─ WEBSITES:
│  └─ WordPress instalations from WP Toolkit & Softaculous 
├─ DATABASES:
│    ├─ MySQL databases, users and grants
│    ├─ PostgreSQL databases, users and grants
│    └─ Remote access to MySQL
├─ PHP:
│    └─ Installed version from Cloudlinux PHP Selector
├─ FTP:
│    └─ FTP accounts with their paths
├─ FILES
├─ CRONS
└─ ACCOUNT
    ├─ Account Password
    ├─ Notification preferences
    ├─ Creation date
    └─ Locale (Language)

***nodejs/python apps are not yet supported***

--------------------------------------------------------------------
  if you experience any errors with this script, please report to
    https://github.com/stefanpejcic/cPanel-to-OpenPanel/issues
--------------------------------------------------------------------
"
}


# MAIN
main() {
    start_message                                                              # what will be imported
    log_paths_are                                                              # where will we store the progress
    
    # STEP 1. PRE-RUN CHECKS
    check_if_valid_cp_backup "$backup_location"                                # is it?
    check_if_disk_available                                                    # calculate du needed for extraction
    check_if_user_exists                                                       # make sure we dont overwrite user!
    validate_plan_exists                                                       # check if provided plan exists
    install_dependencies                                                       # install commands we will use for this script
    get_server_ipv4                                                            # used in mysql grants

    # STEP 2. EXTRACT
    create_tmp_dir_and_path                                                    # create /tmp/.. dir and set the path
    prepare_extraction_source "$backup_location"                               # decompress gzipped archives once, reused below
    validate_archive_paths                                                     # reject archives with path traversal entries (Zip Slip)
    extract_cpanel_backup "$backup_location" "${backup_dir}"                   # extract the archive

    # STEP 3. IMPORT
    locate_backup_directories                                                  # get paths from backup
    parse_cpanel_metadata                                                      # get data and configurations
    create_new_user "$cpanel_username" "random" "$cpanel_email" "$plan_name"   # create user data and container
    dry_run "Would set unlimited quota during the import" || setquota -u $cpanel_username 0 0 0 0 /  # set unlimited quota while we do import!
    restore_files                                                              # homedir, after user-add so /home/$cpanel_username belongs to the new user
    create_home_mountpoint                                                     # mount /var/www/html/ to /home/USERNAME 
    get_mysql_type_cnf_and_socket                                              # mysql or mariadb, path to socket and my.cnf logins
    #NOT NEEDED ON CPANEL #fix_perms                                           # fix permissions for all files
    restore_php_version "$php_version"                                         # php v needs to run before domains 
    restore_domains                                                            # add domains
    restore_dns_zones                                                          # add dns 
    restore_mysql "$mysqldir"                                                  # mysql databases, users and grants
	restore_psql "$psqldir"                                                    # postgresql databases, users and grants
    restore_cron                                                               # cronjob
    restore_ssl "$cpanel_username"                                             # ssl certs
    restore_wordpress "$real_backup_files_path" "$cpanel_username"             # import wp sites to sitemanager
    restore_notifications "$real_backup_files_path" "$cpanel_username"         # notification preferences from cp
    restore_startdate "$real_backup_files_path" "$cpanel_username"             # cp account creation date
    dry_run "Would restore quota" || opencli user-quota --update $cpanel_username  # restore quota

    # STEP 4. IMPORT ENTERPRISE FEATURES
    import_email_accounts_and_data "$cpanel_username"                          # import emails, filters, forwarders..
    ftp_accounts_import "$cpanel_username"                                     # import ftp accounts

	restore_locale                                                             # language
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
# only when executed, so the functions can also be sourced without starting an import
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    define_data_and_log "$@"
fi
