<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides AD group show details functionality. The following options are available:
 1. Search and select the target AD group
 2. Show basic AD group attributes of selected target group
 3. Show current AD members of selectef target group


## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.2   | Added a comment line in the task | 2022/08/12  |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/03  |
| 1.0.0   | Initial release | 2021/06/18  |
 
<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)
* [Getting help](#getting-help)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'AD-group-generate-table-wildcard-show-details'
This Powershell data source runs an Active Directory query to search for matching AD groups.

### Powershell data source 'AD-group-generate-table-attributes-basic-show-details'
This Powershell data source runs an Active Directory query to select a list of basic group attributes of the selected AD group.  

### Powershell data source 'AD-group-generate-table-groupmemberships-show-details'
This Powershell data source runs an Active Directory query to receive the list of current members based on the selected target AD group.

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/505-helloid-sa-active-directory-ad-group-show-details)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
