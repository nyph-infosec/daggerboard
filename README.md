<!--
SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital

SPDX-License-Identifier: MIT
-->

```
____                                ____                      _ 
|  _ \  __ _  __ _  __ _  ___ _ __  | __ )  ___   __ _ _ __ __| |
| | | |/ _` |/ _` |/ _` |/ _ \ '__| |  _ \ / _ \ / _` | '__/ _` |
| |_| | (_| | (_| | (_| |  __/ |    | |_) | (_) | (_| | | | (_| |
|____/ \__,_|\__, |\__, |\___|_|    |____/ \___/ \__,_|_|  \__,_|
              |___/ |___/                                         
```

## _SBOM Vulnerability Scanner Tool_

[![License: Unlicense](https://img.shields.io/badge/license-MIT-blue)](http://unlicense.org/) [![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-brightgreen)]() [![Build Status](https://img.shields.io/badge/Build-Production-green)](https://travis-ci.org/joemccann/dillinger) [![REUSE status](https://api.reuse.software/badge/git.fsfe.org/reuse/api)](https://api.reuse.software/info/git.fsfe.org/reuse/api)


DaggerBoard is a vulnerability scanning tool that ingests Software Bill of Material (SBOM) files (CycloneDX,SPDX) and outputs results in a human-readable format. This tool evaluates software dependencies outlined within the SBOM file for package vulnerabilities. Similar to how the DaggerBoard keeps a ship afloat, the Daggerboard application assists with keeping your organization afloat by analyzing and maintaining risk levels.


#### System Dependencies
---
- Any version of Docker (if using docker installation method)
- 20 GB of available disk space
- Python 3.8
- Tested on Ubuntu 18 and 20.04
- Ubuntu 18 or 20.04 package dependencies:
   ```
    python3-pip python3-django apache2-bin apache2-data apache2-utils apache2 libapache2-mod-wsgi-py3 wget vim cron mariadb-server libmariadb-dev libmariadb3 libmariadbclient-dev libsasl2-dev redis curl libsasl2-dev libldap2-dev
   ```



#### Features
---
- Dashboard to provide at-a-glance views of SBOMS and associated vulnerabilites.
- Provides in-depth analysis on vendor scorecards for given SBOMS.
- Import SPDX or CycloneDX file to detect vulnerabilities.
- Calculates single SBOM Grade or overall Vendor grade.
- Admin interface for managing users and data.
- Supports local and LDAP authentication.



### Tech Stack

---

DaggerBoard uses a number of open-source projects. Listed below are the main packages. For a complete listing of libraries please see the requirements.txt:

- [django] - A high-level Python web framework [Link to license](https://github.com/django/django/blob/main/LICENSE)
- [django-rq] - Django integration for RQ (Redis Queue)[Link to license](https://github.com/rq/django-rq/blob/master/LICENSE.txt)
- [mariaDB] - commercially supported fork of the MySQL relational database. [Link to license](https://github.com/MariaDB/server/blob/10.9/COPYING)
- [pandas] - For data manipulation and analysis. [Link to license](https://github.com/pandas-dev/pandas/blob/main/LICENSE)
- [Bootstrap] - Great UI boilerplate for modern web apps. [Link to license](https://github.com/twbs/bootstrap/blob/main/LICENSE)
- [Chart.js] - JavaScript library for data visualization [Link to license](https://github.com/chartjs/Chart.js/blob/master/LICENSE.md)
- [jQuery] - JavaScript library designed to simplify HTML DOM [Link to license](https://github.com/jquery/jquery/blob/main/LICENSE.txt)




#### Getting started

---
Two installation methods are provided: Docker and an installer script. The two installation options can be downloaded [on the project releases page](https://github.com/nyph-infosec/daggerboard/releases). For manual installation steps, see the section **Manual Install**.

##### Option 1 - Installer Script
1. Make the .bin executable
```
chmod +x DaggerBoard_Installer.bin
```

2. Run the binary to install the application
```
sudo ./DaggerBoard_Installer.bin
```
Note: You will be prompted to enter an admin password and IP address of the server.

3. Reboot the server


##### Option 2 - Docker
1. Load the package into Docker


```
sudo gunzip daggerboard_docker_image.tgz
sudo docker load --input daggerboard_docker_image.tar
```

2. Run the container
```
sudo docker run -p443:443 -d -v dagger-vol:/var/lib/mysql daggerboard:version1
```

#### Manual Install Steps
---
To install DaggerBoard on an OS that is not supported, you must ensure that you have the necessary OS dependencies prior to running steps outlined in the installer script.

Install the OS equivalent of the following on your system:
   ```
    python3-pip
    python3-django
    apache2-bin
    apache2-data
    apache2-utils
    apache2
    libapache2-mod-wsgi-py3
    wget
    vim
    cron
    mariadb-server
    libmariadb-dev
    libmariadb3
    libmariadbclient-dev
    libsasl2-dev
    redis
    curl
    libsasl2-dev
    libldap2-dev
   ```



#### Proxy Configuration

Use the .env file to set the proxy configuration.

```
1. Edit the file /var/www/Daggerboard/daggerboardproject/.env
2. Add proxy server to the PROXY= variable

Ex: PROXY=https://proxy.example.com:8080
```


#### Environment Configurations
---

 The .env file located in ```/var/www/Daggerboard/daggerboardproject/.env ``` Please use this file to configure your environment.

| Environment Variable      | Default | Description    |
| :---        |    :----   |          :--- |
| ```PROXY``` | Optional. No default | If internet is provided via proxy, please enter address here. |
| ```LOGPATH``` | ```/var/www/Daggerboard/logs/``` | Location path of log file. |
| ```DBHOST``` | ```localhost``` | Hostname of database. |
| ```DBPASSWORD``` | ```daggerboard``` | Database password. |
| ```REDISPWD``` | ```daggerboard_redis``` | Redis password. |
| ```REDISHOST``` |```localhost``` | Redis hostname. |
| ```LDAP_BIND_PROTECTION``` | Required. Defaulted | Random 32-character key generated by default. |
| ```SBOMPROCESS_LOGPATH``` |```/var/www/sbomscripts/sbom``` | Log path of SBOM uploads. |


#### Initial Authentication
---
The superuser is automatically configured for your environment:

```
Username: admin
Password: daggerboard
```

Please change the password in the DaggerBoard Admin panel.




#### SBOM Upload Process

 ---

![Daggerboard Diagram](/.attachments/readme_db_diagram.png)



**CRON background processes**: 
- Retrieve CVE data from the NVD Website feed on Recent & Modified feeds daily and store in **local data object**. [https://nvd.nist.gov/vuln/data-feeds]()
- Retrieve CVE data from the NVD website feed on all CVE data listed since 2002 monthly and store in **local data object**.

**User provided data**: 
1. User Uploads SPDX or CycloneDX SBOM.
2. The SBOM is parsed and correlation is performed against the **local data object** for CPE.
   * If a match is found:
      *	Get the CVSS score.
      * Scrape ExploitDB based on the CVE for any exploits that exist. [https://www.exploit-db.com/]
      * Daggerboard database is populated.
      * User is prompted on successful upload.
   * If not matched:
      * A detailed search is performed on NVD website to match the CPE to the version.
      * If the detailed search finds a match:
         * Scrape ExploitDB based on the CVE for any exploits that exist. [https://www.exploit-db.com/]
         * Daggerboard database is populated.
         * User is prompted on successful upload.
      * If the detailed search does not find a match:
         * A “Not Found” comment is generated.
         * Populate the Daggerboard database.
         * User is prompted on successful upload.


#### Grading Policy

---

Each severity level (critical, high, medium, low) comes from the CVE assigned to a vulnerability which is sourced from NVD. This information from NVD is collected in a database and assigned to the respective packages from the SBOM based on CPE. Each of the severities are counted and totaled which can be based on either a vendor or individual SBOM level.

As part of our scoring system, we use multipliers which are weights that are assigned to each severity. These weights are set by default but can be configured in the admin settings.
 
>The count of Critical is multiplied by **40**
>The count of High is multiplied by **10**
>The count of Medium is multiplied by **3**
>The count of Low is multiplied by **1**
 
The **weighted sum** is equal to the sum of the severities multiplied for a particular SBOM or vendor.
 
Final Grade = (**weighted sum**) / 54 (40 + 10 + 3 + 1)

Letter grade thresholds are also set by default and can be configured in the admin settings:
>Final Grade <= 1: **A**
>Final Grade >= 2 and < 4: **B**
>Final Grade >= 4 and < 6: **C**
>Final Grade >= 6 and < 8: **D**
>Final Grade > 8: **F**


#### Authentication Using LDAP
---
Daggerboard supports the option to implement LDAP by adding your LDAP configuration within the daggerboard admin panel. Under _authentication and authorization_ you will need to provide the following values that are related to your LDAP environment:


```
SERVER URI	         Server URI should begin with ldap:// or ldaps://
BIND DN	                 Location of the authorized account in the LDAP directory tree
BIND PASSWORD	         The password to be used with the BIND DN
USER SEARCH	         Object that will locate a user in the directory.
GROUP SEARCH	         Object that finds all LDAP groups that users might belong to.
AUTH LDAP GROUP TYPE	 Instance describing the type of group returned by GROUP SEARCH.
AUTH LDAP REQUIRE GROUP	 The distinguished name of a group; authentication will fail for any user that does not belong to this group.
``` 

#### How to Contribute

---

All contributions are welcome!
Please take a moment to review the [DaggerBoard Contribution Guide](CONTRIBUTING.md).


#### Future Work

---
* Advanced reporting and analytics.
* API Integrations
* Email and scheduled report options.
* Enhancements to SBOM search functionality to search by CVE.


#### Contributors

---

- Will Landymore
- Valton Hashani
- Katie Bratman
- Jay Benfield
- Adam Kojak
- Tony Vu

#### License 

---

This project is licensed under the terms of the [MIT license](LICENSE.md).


#### Release Notes

---
* Version 1.0.0 Initial  of DaggerBoard
