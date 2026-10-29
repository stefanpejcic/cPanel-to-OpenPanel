# shellcheck shell=bash
# cp-import.sh step: FTP accounts, sourced by cp-import.sh

# ======================================================================
# FTP
ftp_accounts_import() {
	cpanel_username="$1"
    [ ! -f "$ftp_conf" ] && { log "No FTP config file not found: $ftp_conf"; return 1; }

	read -r total_accounts created_accounts < <(awk '!/^#/ && !/^$/ {total++; if ($0 ~ /@/) created++} END {print total+0, created+0}' "$ftp_conf")

	dry_run "Would restore $created_accounts / $total_accounts FTP accounts from $ftp_conf file (system accounts are excluded)" && return
    log "INFO: Importing $created_accounts / $total_accounts FTP accounts (system accounts are excluded)"

	: '
	cpanel format:	  <USERNAME>:<HASHED_PASS>:<UID>:<GID>:<CP_USERNAME>:<PATH>:<SHELL>
	openpanel format: <USERNAME>|<HASHED_PASS>|<PATH>|<UID>|<GID>
	'

	users_list="/etc/openpanel/ftp/users/${cpanel_username}/users.list"
    mkdir -p "$(dirname "$users_list")"
    touch "$users_list"
	dummy_pass=$(openssl rand -base64 12 | tr -d '=+/')
	# the uid/gid in proftpdpasswd belong to the old cPanel server, run FTP as the account so uploads are owned like its other files
	local account_uid
	account_uid=$(stat -c '%u' "/home/$cpanel_username")

	while IFS=: read -r username pass _ _ owner home shell; do

        [ -z "$username" ] && continue
        [[ "$username" == \#* ]] && continue

        # skip system user
        [[ "$username" != *@* ]] && { log "SKIP: system FTP account $username"; continue; }

        folder="$home"
        folder="${folder/\/home\/$cpanel_username/\/var\/www\/html}"

		log "Importing: $username -> $folder"
        sed -i "\|^${username}|d" "$users_list"
        echo "${username}|${pass}|${folder}|${account_uid}|${account_uid}" >> "$users_list"

    done < "$ftp_conf"

	actually_imported=$(wc -l < "$users_list")
	log "Finished importing FTP accounts: $actually_imported"

	# nothing to load, so don't turn on an FTP server the admin may never have enabled
	[ "$actually_imported" -gt 0 ] || return 0

	# openadmin_ftp is a system container, ask root's podman like opencli ftp-add does, not the user's
	. /usr/local/opencli/lib/podman.sh
	if podman_is_running openadmin_ftp; then
		log "FTP service is running, reloading.."
		podman restart openadmin_ftp >/dev/null 2>&1
	else
		log "FTP service is not running, starting.."
		podman_ensure_running openadmin_ftp /root openadmin_ftp >/dev/null 2>&1
	fi
}
