# CyberPanel 2 OpenPanel account import
Free OpenPanel module to import CyberPanel backup in OpenPanel

Maintained by [CodeWithJuber](https://github.com/CodeWithJuber)

## Features

Currently suported for import:
```
├─ DOMAINS:
│  ├─ Primary domain, Addons, Aliases and Subdomains
│  └─ SSL certificates
├─ WEBSITES:
│  └─ WordPress instalations
├─ DATABASES:
│    └─ MySQL databases and users
├─ PHP:
│    └─ PHP versions per domain
├─ FILES
└─ ACCOUNT
    └─ CyberPanel account password

***emails, crons, dns, ftp, nodejs/python, postgres are not yet supported***
```

## Usage

Run the script with sudo privileges:

```
git clone -b cyberpanel https://github.com/stefanpejcic/cPanel-to-OpenPanel.git
```

```
bash cPanel-to-OpenPanel/cp-import.sh --backup-location=/path/to/cyberpanel_backup.file --plan-name='Standard plan'
```

## Parameters

- `--backup-location=` Path to the CyberPanel backup file
- `--plan-name=`      Name of the hosting plan in OpenPanel
- `--dry-run`         extract archive and display data without actually importing account

## Disclaimer

This script is provided as-is, without any guarantees. Always test thoroughly in a non-production environment before using in production.
