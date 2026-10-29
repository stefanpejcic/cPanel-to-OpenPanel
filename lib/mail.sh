# shellcheck shell=bash
# cp-import.sh step: email accounts and mailboxes, sourced by cp-import.sh

# ======================================================================
# EMAILS
import_email_accounts_and_data() {
    local cpanel_username="$1"

    log "Restoring email accounts and mailboxes"

    local base_dir="/home/$cpanel_username/docker-data/volumes/${cpanel_username}_html_data/_data/etc"
	
	dry_run "Would restore email accounts from $base_dir" && return

	postfix_file="/usr/local/mail/openmail/docker-data/dms/config/postfix-accounts.cf"
	mailserver_dir="/usr/local/mail/openmail/docker-data/dms/config/"
	if [ ! -d "$mailserver_dir" ]; then
		log "WARNING: Skipping email imports due to mailserver not configured."
		return 0
	fi

	# 1: check where openadmin is configured to store mail data
	STORE_EMAILS_IN=$(grep -E '^email_storage_location=' /etc/openpanel/openadmin/config/admin.ini | cut -d'=' -f2- | xargs)
	[[ "$STORE_EMAILS_IN" == /* ]] || STORE_EMAILS_IN=""

    if [ -f "$real_backup_files_path/cp/$cpanel_username" ]; then
    	local mailbox_format=$(grep '^MAILBOX_FORMAT=' "$real_backup_files_path/cp/$cpanel_username" | cut -d'=' -f2 | cut -c1-2 | tr '[:upper:]' '[:lower:]')
	    if [ "$mailbox_format" = "maildir" ] || [ "$mailbox_format" = "ma" ]; then
			:
		elif [ "$mailbox_format" == "mbox" ]; then
			log "WARNING: Emails will not be imported because the cPanel account uses 'mbox' format, while OpenPanel uses 'maildir'. Emails remain available in /var/www/html/mail/."
		else
			log "WARNING: Emails will not be imported because the mailbox format could not be detected. Emails remain available in /var/www/html/mail/."
		fi
	fi

	local temp_email_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)

	OPENPANEL_UID=$(id -u $cpanel_username)

    for dir_path in "$base_dir"/*/; do
		local domain
	    shadow_file="$dir_path/shadow"
	    if [[ -f "$shadow_file" && -s "$shadow_file" ]]; then
	        domain=$(basename "$dir_path")
			local store_dir="${STORE_EMAILS_IN:-/home/$cpanel_username/mail/$domain/}"
	        owner=$(opencli domains-whoowns "$domain" | awk -F': ' '{print $2}')
	        if [[ "$owner" == "$cpanel_username" ]]; then
				# cpanel format: <user>:<sha_hash>/:<uid>::::::
				while IFS=: read -r username password_hash rest; do
				    [[ -z "$username" || -z "$password_hash" ]] && continue
				    email="${username}@${domain}"
				    log "Importing mailbox: $email"
				    opencli email-setup email add "$email" "$temp_email_password" >/dev/null 2>&1
					# openpanel format: <user>@<domain>|{SHA512-CRYPT}<sha_hash>|<uid>
					sed -i.bak "/^${email}|/c\\${email}|{SHA512-CRYPT}${password_hash}|${OPENPANEL_UID}" "$postfix_file"
				done < "$shadow_file"

				# 2. move mails
				# openpanel stores emails in: $STORE_EMAILS_IN/<domain>/<user>
				if [ "$mailbox_format" = "maildir" ] || [ "$mailbox_format" = "ma" ]; then
					# cpanel stores email in: extract/<backup_filename>/homedir/mail/<domain>/<user>
					if [ -d "/home/$cpanel_username/docker-data/volumes/${cpanel_username}_html_data/_data/mail/$domain/$username" ]; then
						log "Restoring mailboxes to $STORE_EMAILS_IN/$domain/"
						rsync -av --remove-source-files "/home/$cpanel_username/docker-data/volumes/${cpanel_username}_html_data/_data/mail/$domain/." "$store_dir/$domain/"
					else
						log "Failed restoring mailbox to $STORE_EMAILS_IN - $base_dir/mail/$domain/$username does not exist"
					fi
				else
					log "WARNING: messages will not be moved due to unsupported mailbox format: $mailbox_format. More info on how to convert to maildir: https://docs.cpanel.net/whm/email/mailbox-conversion/"
				fi
	        else
	            log "Skipping $domain: not owned by user $cpanel_username."
	        fi
	    else
	        log "Skipping $dir_path (shadow file missing or empty)"
	    fi
    done
}
