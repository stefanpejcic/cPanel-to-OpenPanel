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
