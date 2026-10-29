# shellcheck shell=bash
# cp-import.sh step: domains, DNS zones, SSL certificates and WordPress sites, sourced by cp-import.sh

# ======================================================================
# SSL CERTIFICATES
restore_ssl() {
    local username="$1"

    dry_run "Would restore SSL certificates for user $username" && return

    # TODO: edit to cover certs/ keys/ 
    log "Restoring SSL certificates"
    # apache_tls/ dir has LE certs, custom are in ssl/
    if [ -d "$real_backup_files_path/ssl" ]; then
        dest_dir="/home/$username/docker-data/volumes/${username}_html_data/_data/"
		shopt -s nullglob
        for cert_file in "$real_backup_files_path/ssl"/*.crt; do
            local domain=$(basename "$cert_file" .crt)
            local key_file="$real_backup_files_path/ssl/$domain.key"
            local new_cert_file="$dest_dir/$domain.crt"
            local new_key_file="$dest_dir/$domain.key"
            if [ -f "$key_file" ]; then
                cp "$key_file" "$new_key_file"
                cp "$cert_file" "$new_cert_file"         
			    if [[ "$domain" == *.cpanel.site ]]; then
			        echo "Skipping cPanel temporary domain: $domain"
			        continue
			    fi
				log "Installing SSL certificate for domain: $domain"
                opencli domains-ssl "$domain" custom "/var/www/html/$domain.key" "/var/www/html/$domain.crt"
				rm -rf "$new_cert_file" "$new_key_file"
            else
                log "SSL key file not found for domain: $domain"
            fi
        done

        nohup podman exec caddy caddy reload --config /etc/caddy/Caddyfile > /dev/null 2>&1 &
        disown

    else
        log "No SSL certificates found to restore"
    fi
}

# ======================================================================
# DNS ZONES
restore_dns_zones() {
    log "Restoring DNS zones"

    dry_run "Would restore DNS zones for user $cpanel_username" && return

    if [ -d "$real_backup_files_path/dnszones" ]; then
        for zone_file in "$real_backup_files_path/dnszones"/*; do
            local zone_name=$(basename "${zone_file%.db}")
			
			if [[ "$zone_name" == *.cpanel.site ]]; then
			    log "Skipping cPanel temporary domain: $zone_name"
			    continue
            fi

            if [ ! -f "/etc/bind/zones/${zone_name}.zone" ]; then
                log "DNS zone file /etc/bind/zones/${zone_name}.zone does not exist. Skipping import for $zone_name."
                continue
			fi

            old_ip=$(grep -oP 'IP=\K[0-9.]+' ${real_backup_files_path}/cp/$cpanel_username)
            if [ -z "$old_ip" ]; then
                log "WARNING: old server ip address not detected in file ${real_backup_files_path}/cp/$cpanel_username - records will not be automatically updated to new ip address."
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

# ======================================================================
# WORDPRESS SITES
restore_wordpress() {
    local real_backup_files_path="$1"
    local username="$2"

    dry_run "Would restore WordPress sites for user $username" && return

    log "Checking user files for WordPress installations to add to Site Manager interface.."
    output=$(opencli websites-scan $cpanel_username)
        while IFS= read -r line; do
            log "$line"
        done <<< "$output"    
}

# ======================================================================
# DOMAINS
restore_domains() {
    if [ -f "$real_backup_files_path/userdata/main" ]; then
        file_path="$real_backup_files_path/userdata/main"
        main_domain=""
        parked_domains=""
        sub_domains=""
        addon_domains=""

		parked_domains_section=false
		sub_domains_section=false
		addon_domains_section=false


        while IFS= read -r line; do
            if [[ "$line" =~ ^main_domain: ]]; then
                main_domain=$(echo "$line" | awk '{print $2}')
			elif [[ "$line" =~ ^parked_domains: ]]; then
			    parked_domains_section=true
			    sub_domains_section=false
			    addon_domains_section=false
			    continue
			elif [[ "$line" =~ ^sub_domains: ]]; then
			    sub_domains_section=true
			    parked_domains_section=false
			    addon_domains_section=false
			    continue
			elif [[ "$line" =~ ^addon_domains: ]]; then
			    addon_domains_section=true
			    parked_domains_section=false
			    sub_domains_section=false
			    continue
            fi

            if [[ "$sub_domains_section" == true ]]; then
                if [[ "$line" =~ ^[[:space:]]+- ]]; then
                    sub_domains+=$(echo "$line" | awk '{print $2}')$'\n'
                else
                    sub_domains_section=false
                fi
            fi

            if [[ "$parked_domains_section" == true ]]; then
                if [[ "$line" =~ ^[[:space:]]+- ]]; then
                    parked_domains+=$(echo "$line" | awk '{print $2}')$'\n'
                else
                    parked_domains_section=false
                fi
            fi

            if [[ "$addon_domains_section" == true ]]; then
                if [[ "$line" =~ ^[[:space:]]*[^:]+:[[:space:]]*[^[:space:]]+$ ]]; then
                    domain=$(echo "$line" | awk -F: '{print $1}' | tr -d '[:space:]')
                    if [[ -n "$domain" && "$domain" != "main_domain" && "$domain" != "parked_domains" ]]; then
                        addon_domains+="$domain"$'\n'
                    fi
                else
                    addon_domains_section=false
                fi
            fi
        done < "$file_path"

        sub_domains_array=()
        addon_domains_array=()
		parked_domains_array=()

        # Parse sub_domains
        while IFS= read -r domain; do
            if [[ -n "$domain" ]]; then
                sub_domains_array+=("$domain")
            fi
        done <<< "$sub_domains"

        # Parse addon_domains
        while IFS= read -r domain; do
            if [[ -n "$domain" ]]; then
                addon_domains_array+=("$domain")
            fi
        done <<< "$addon_domains"

        # Parse parked_domains
        while IFS= read -r domain; do
            if [[ -n "$domain" ]]; then
                parked_domains_array+=("$domain")
            fi
        done <<< "$parked_domains"

        # Filter out subdomains that are essentially addon_domain.$main_domain
        filtered_sub_domains=()
        for sub_domain in "${sub_domains_array[@]}"; do
            trimmed_sub_domain=$(echo "$sub_domain" | xargs)
            is_addon=false
            for addon in "${addon_domains_array[@]}"; do
                if [[ "$trimmed_sub_domain" == "$addon.$main_domain" ]]; then
                    is_addon=true
                    break
                fi
            done
            if [ "$is_addon" = false ]; then
                filtered_sub_domains+=("$trimmed_sub_domain")
            fi
        done

		main_domain_count=1
		log "Primary domain ($main_domain_count): $main_domain"

        addon_domains_count=${#addon_domains_array[@]}
        if [ "${#addon_domains_array[@]}" -eq 1 ] && [ -z "${addon_domains_array[0]}" ]; then
            addon_domains_count=0
            log "No addon domains detected."
        else
            log "Addon domains  ($addon_domains_count): ${addon_domains_array[@]}"
        fi

        parked_domains_count=${#parked_domains_array[@]}
        if [ "${#parked_domains_array[@]}" -eq 1 ] && [ -z "${parked_domains_array[0]}" ]; then
            parked_domains_count=0
            log "No parked domains detected."
        else
            log "Parked domains ($parked_domains_count): ${parked_domains_array[@]}"
        fi

        filtered_sub_domains_count=${#filtered_sub_domains[@]}
        if [ "${#filtered_sub_domains[@]}" -eq 1 ] && [ -z "${filtered_sub_domains[0]}" ]; then
            filtered_sub_domains_count=0
            log "No subdomains detected."
        else
            log "Subdomains     ($filtered_sub_domains_count): ${filtered_sub_domains[@]}"
        fi


        domains_total_count=$((main_domain_count + addon_domains_count + parked_domains_count + filtered_sub_domains_count))

        log "Detected a total of $domains_total_count domains"

        current_domain_count=0

        create_domain(){
            domain="$1"
            type="$2"

            current_domain_count=$((current_domain_count + 1))

		    if [[ "$domain" == *.cpanel.site ]]; then
		        log "Skipping cPanel temporary domain: $domain"
		        return 0
		    fi
			
            if [[ $domain == \*.* ]]; then
                log "WARNING: Skipping wildcard domain $domain"
				return 0
            fi
			log "Restoring $type $domain (${current_domain_count}/${domains_total_count})"

			local userdata_file="$real_backup_files_path/userdata/$domain"
			local addon_userdata_file="$real_backup_files_path/userdata/$domain.$main_domain"
			file_to_use="$userdata_file"
			[ ! -f "$file_to_use" ] && [ -f "$addon_userdata_file" ] && file_to_use="$addon_userdata_file"
			
			docroot=""
			if [ -f "$file_to_use" ]; then
				original_docroot=$(awk -F': ' '/^documentroot:/ {print $2}' "$file_to_use" | xargs)
			    docroot="${original_docroot#/home/$cpanel_username/}"
			    docroot="/var/www/html/$docroot"
			else
				log "WARNING: userdata file not found for $domain. Using default docroot."
			fi

			dry_run "Would restore $type $domain with --docroot ${docroot:-N/A}" && return

			if opencli domains-whoowns "$domain" | grep -q "not found in the database."; then
				if [ -n "$docroot" ]; then
					output=$(opencli domains-add "$domain" "$cpanel_username" --docroot "$docroot" 2>&1)
					while IFS= read -r line; do
						log "$line"
					done <<< "$output"
				else
					output=$(opencli domains-add "$domain" "$cpanel_username" 2>&1)
					while IFS= read -r line; do
						log "$line"
					done <<< "$output"                        
				fi
				if [ -f "$real_backup_files_path/userdata/$domain" ]; then
					local secruleengineoff=$(grep '^secruleengineoff=' "$real_backup_files_path/userdata/$domain" | cut -d'=' -f2 | cut -c1-2 | tr '[:upper:]' '[:lower:]')
					if [ "$secruleengineoff" == "1" ]; then
						log "Disabling WAF because ModSecurity is turned off for this domain in cPanel."
						output=$(opencli waf domain "$domain" "disable" 2>&1)
						while IFS= read -r line; do
							log "$line"
						done <<< "$output"
					fi
				fi
			else
				log "WARNING: $type $domain already exists and will not be added to this user."
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
