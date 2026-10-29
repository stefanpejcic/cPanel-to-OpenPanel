# shellcheck shell=bash
# cp-import.sh step: logging, dry-run, cleanup and dependency helpers shared by every step, sourced by cp-import.sh

log() {
    if [[ -z "${1// /}" ]]; then
        return
    fi
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

debug_log() {
    if [ "$DEBUG" = true ]; then
        log "DEBUG: $1"
    fi
}

dry_run() {
    local msg="$1"
    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: $msg"
        return 0
    fi
    return 1
}

handle_error() {
    log "FATAL ERROR: An error occurred in function '$1' on line $2"
    cleanup
    exit 1
}

cleanup() {
    log "Cleaning up temporary files and directories"
    rm -rf "$backup_dir"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_dependencies() {
    log "Checking and installing dependencies..."
    install_needed=false
    commands=(jq curl rsync)

	[[ "$backup_filename" == *.zip ]] && commands+=(unzip)
	[[ "$backup_filename" == *.tar || "$backup_filename" == *.tar.gz || "$backup_filename" == *.tgz || "$backup_filename" == *.gz ]] && commands+=(tar pigz)
		

    for cmd in "${commands[@]}"; do
        command_exists "$cmd" || { install_needed=true; break; }
    done

    if [ "$install_needed" = true ]; then
        if command_exists apt-get; then
            log "Detected APT package manager. Updating..."
            apt-mark hold linux-image-generic linux-headers-generic >/dev/null 2>&1
            #apt-get update -y >/dev/null 2>&1
            for cmd in "${commands[@]}"; do
                if ! command_exists "$cmd"; then
                    log "Installing $cmd (APT)"
                    apt-get install -y --no-upgrade --no-install-recommends "$cmd" >/dev/null 2>&1
                fi
            done
            apt-mark unhold linux-image-generic linux-headers-generic >/dev/null 2>&1
        elif command_exists dnf; then
            log "Detected DNF package manager. Updating..."
            dnf -y makecache >/dev/null 2>&1
            for cmd in "${commands[@]}"; do
                if ! command_exists "$cmd"; then
                    log "Installing $cmd (DNF)"
                    dnf install -y "$cmd" >/dev/null 2>&1
                fi
            done
        else
            log "Error: Unsupported package manager. Please install dependencies manually."
            exit 1
        fi
        log "Dependencies installed successfully."
    else
        log "All required dependencies are already installed."
    fi
}

get_server_ipv4(){
    new_ip=$(curl --silent --max-time 2 -4 https://ip.openpanel.com || curl --silent --max-time 2 -4 https://ifconfig.me)
    if [ -z "$new_ip" ]; then
        new_ip=$(ip addr|grep 'inet '|grep global|head -n1|awk '{print $2}'|cut -f1 -d/)
    fi
}
