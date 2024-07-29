# cPanel-to-OpenPanel
Free OpenPanel module to import cPanel backup in OpenPanel

Maintained by [CodeWithJuber](https://github.com/CodeWithJuber)

## Plan

This repository will host files for the cPanel2OpenPanel module.

Module will be used to import cPanel backup either from local or remote url, and create a new OpenPanel account with all the data from backup: files, databases, users, etc.


Steps:
- create a dummy backup for a cpanel account that contains all the data needed for restore
- unzip, examine the data structure, and create a list to map files/locatiosn that we need for each import operation.
- create a python script to perform the actuall imports
- create OpenAdmin module and template
- include in OpenAdmin


# cPanel to OpenPanel Migration Script

This script automates the process of migrating a cPanel backup to an OpenPanel system. It handles various cPanel backup formats and restores essential components of the user's account.

## Features

- Supports multiple cPanel backup formats (cpmove, full backup, tar.gz, tgz, tar, zip)
- Restores user account details, domains, and hosting plan settings
- Migrates websites, databases, email data, SSL certificates, and DNS zones
- Handles PHP version settings and cron jobs
- Restores SSH access and file permissions

## Prerequisites

- Root or sudo access on the OpenPanel server
- OpenPanel CLI (`opencli`) installed and configured
- Sufficient disk space for extracting and processing the backup

## Usage

1. Run the script with sudo privileges:

sudo ./cp-import.sh --backup-location /path/to/cpanel_backup.file --plan-name "Plan Name" --docker-image openpanel/base:latest

Replace the following:
- `/path/to/cpanel_backup.file`: Path to your cPanel backup file
- `"Plan Name"`: Name of the hosting plan to create or use in OpenPanel
- `openpanel/base:latest`: Docker image for your OpenPanel setup

## Parameters

- `--backup-location`: Path to the cPanel backup file (required)
- `--plan-name`: Name of the hosting plan in OpenPanel (required)
- `--docker-image`: Docker image for OpenPanel (required)

## Supported Operating Systems

- Debian-based systems (e.g., Ubuntu)
- Red Hat-based systems (e.g., CentOS)
- AlmaLinux

The script will attempt to install necessary dependencies on these systems. For other operating systems, you may need to install required packages manually.

## Important Notes

- This script should be run on the OpenPanel server where you want to import the cPanel backup.
- Ensure that you have a full backup of your OpenPanel system before running this script.
- The script requires internet access to install dependencies if they are not already present.
- Large backups may take a considerable amount of time to process.
- Some manual configuration may be required after the migration, depending on the complexity of the cPanel account.

## Troubleshooting

If you encounter any issues:

1. Check the script's output for error messages.
2. Verify that all prerequisites are met.
3. Ensure you have sufficient disk space and system resources.
4. Check the OpenPanel logs for any additional error information.

## Contributing

Contributions to improve the script are welcome. Please feel free to submit issues or pull requests.

## License

[MIT License](LICENSE)

## Disclaimer

This script is provided as-is, without any guarantees. Always test thoroughly in a non-production environment before using in production.
