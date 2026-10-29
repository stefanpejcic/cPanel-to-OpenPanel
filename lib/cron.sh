# shellcheck shell=bash
# cp-import.sh step: cron jobs, sourced by cp-import.sh

# ======================================================================
# CRONJOB
restore_cron() {
    log "Restoring cron jobs"
    
    dry_run "Would restore cron jobs for user $cpanel_username" && return

    if [ -f "$real_backup_files_path/cron/$cpanel_username" ]; then
        sed -i '1,2d' "$real_backup_files_path/cron/$cpanel_username"
        ofelia_cron_path="/home/${cpanel_username}/crons.ini"
        > "$ofelia_cron_path"

        job_index=1
        job_found=false
        while IFS= read -r cron_line; do
            [[ -z "$cron_line" || "$cron_line" =~ ^# ]] && continue

            job_found=true
            schedule="* $(echo "$cron_line" | awk '{print $1, $2, $3, $4, $5}')"
            command=$(echo "$cron_line" | cut -d' ' -f6-)

            if [[ "$command" == *mysql* || "$command" == *mariadb* ]]; then
                container_name="$mysql_type"
                comment_prefix=""
            elif [[ "$command" == *php* ]]; then
                container_name="php-fpm-$php_version"
                comment_prefix=""
            else
                container_name=""
                comment_prefix="# "
            fi

            {
                echo "${comment_prefix}[job-exec \"${cpanel_username}_job_$job_index\"]"
                echo "${comment_prefix}schedule = $schedule"
                if [[ -n "$container_name" ]]; then
                    echo "${comment_prefix}container = $container_name"
                fi
                echo "${comment_prefix}command = $command"
                echo
            } >> "$ofelia_cron_path"

            ((job_index++))
        done < "$real_backup_files_path/cron/$cpanel_username"

        if [ "$job_found" = true ]; then
            log "Converted crontab to Ofelia config at: $ofelia_cron_path"
            log "Starting Cron service"
            output=$(cd /home/$cpanel_username && CONTAINER_HOST=unix:///hostfs/run/user/$(id -u $cpanel_username)/podman/podman.sock podman-compose up -d cron >/dev/null 2>&1)           
            while IFS= read -r line; do
                log "$line"
            done <<< "$output"
        else
            log "No cron jobs found in file, not starting cron service"
            rm -f "$ofelia_cron_path"
        fi

    else
        log "No cron jobs found to restore"
    fi
}
