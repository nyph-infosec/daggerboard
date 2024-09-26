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

[![License: Unlicense](https://img.shields.io/badge/license-MIT-blue)](http://unlicense.org/) [![Version: 2.0.0](https://img.shields.io/badge/Version-2.0.0-brightgreen)]() [![Build Status](https://img.shields.io/badge/Build-Development-blue)](https://travis-ci.org/joemccann/dillinger) [![REUSE status](https://api.reuse.software/badge/git.fsfe.org/reuse/api)](https://api.reuse.software/info/git.fsfe.org/reuse/api)


DaggerBoard is a vulnerability scanning tool designed to process Software Bill of Materials (SBOM) files (CycloneDX, SPDX) and present the results in an easy-to-understand format. This tool assesses the software dependencies listed in the SBOM file for potential vulnerabilities. Much like a daggerboard stabilizes a ship, the DaggerBoard application helps your organization stay secure by analyzing and managing risk levels.



#### System Dependencies
---
- 20 GB of available disk space
- Python 3.10
- Tested on Ubuntu 22.04
- Ubuntu 22.04 package dependencies:
   - python3
   - python3-pip
   - python3-venv
   - libldap2-dev
   - libsasl2-dev
   - rabbitmq-server

To install the Ubuntu 22.04 package dependencies, run the following command:

```sh
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv libldap2-dev libsasl2-dev rabbitmq-server
```

#### Features
---
- Dashboard offering an at-a-glance view of SBOMs and their associated vulnerabilities.
- Detailed analysis of vendor scorecards for specific SBOMs.
- Import SPDX or CycloneDX files to identify vulnerabilities.
- Computes grades for individual SBOMs and overall vendor grades.
- Admin interface for user and data management.
- Supports both local and LDAP authentication.

### Tech Stack

---

DaggerBoard leverages several open-source projects. Below are the primary packages used. For a full list of libraries, please refer to the requirements.txt file:

- [django] - A high-level Python web framework [Link to license](https://github.com/django/django/blob/main/LICENSE)
- [django-rq] - Django integration for RQ (Redis Queue)[Link to license](https://github.com/rq/django-rq/blob/master/LICENSE.txt)
- [djangorestframework] - A powerful and flexible toolkit for building Web APIs. [Link to license](https://github.com/encode/django-rest-framework/blob/master/LICENSE.md)
- [pandas] - For data manipulation and analysis. [Link to license](https://github.com/pandas-dev/pandas/blob/main/LICENSE)
- [Bootstrap] - Great UI boilerplate for modern web apps. [Link to license](https://github.com/twbs/bootstrap/blob/main/LICENSE)
- [Chart.js] - JavaScript library for data visualization [Link to license](https://github.com/chartjs/Chart.js/blob/master/LICENSE.md)
- [jQuery] - JavaScript library designed to simplify HTML DOM [Link to license](https://github.com/jquery/jquery/blob/main/LICENSE.txt)




#### Getting started
Follow these steps to set up the Daggerboard project using the provided installation script.

#### Installation Steps

1. **Clone the Repository**

   First, clone the Daggerboard repository to your local machine:

   ```sh
   git clone https://github.com/yourusername/Daggerboard.git
   cd Daggerboard
   ```

2. Run the Installation Script

   Execute the install_daggerboard.sh script to set up the project:

   ```sh
   sudo bash install_daggerboard.sh
   ```
   The script performs the following tasks:
   - Creates necessary directories with appropriate ownership and permissions.
   - Installs required packages and dependencies.
   - Sets up a Python virtual environment and installs the required Python packages.
   - Configures and starts the RabbitMQ server.
   - Configures and starts the Celery service.
   - Runs Django migrations and creates a superuser.
   - Collects static files and compresses them.

3. Post-Installation

   After the installation script completes, you can start the Django development server:

   ```sh
   source /var/www/Daggerboard/venv/bin/activate
   cd /var/www/Daggerboard
   python manage.py runserver 0.0.0.0:8000
   ```
   You should now be able to access the Daggerboard application in your web browser at http://0.0.0.0:8000.

### Troubleshooting

If you encounter any issues during the installation, check the `install.log` file located in the directory where you ran the script. This log file contains detailed information about the installation process and any errors that occurred.

For further assistance, please refer to the project's documentation or contact the support team.

By following these steps, you will have the Daggerboard project set up and running on your local machine.

### Daggerboard API

For detailed information on how to use the Daggerboard API, please refer to the [API Guide](/docs/daggerboard_api_guide.md).


### Environment Configurations

For environment configurations, we will be using the `development.py` configuration file located in `daggerboardproject/settings/`. The following settings are the default configurations provided in the `development.py` file. You may need to update these settings to match your environment.

1. **Locate the Configuration File**

   The `development.py` file is located in the `daggerboardproject/settings/` directory. This file contains all the necessary settings for the development environment.

2. **Default Configuration Settings**

   Below are the default settings provided in the `development.py` file:

   - **Base Directory**: The base directory of your project.
     ```python
     BASE_DIR = '/var/www/Daggerboard/'
     ```

   - **Celery Settings**: Default settings for Celery.
     ```python
     CELERY_BROKER_URL = "amqp://localhost"
     CELERY_RESULT_BACKEND = "db+sqlite:////var/www/Daggerboard/db/tasks.sqlite"
     ```

   - **Database Configuration**: Default database settings.
     ```python
     DATABASES = {
         "default": {
             "ENGINE": "django.db.backends.sqlite3",
             "NAME": os.path.join(BASE_DIR, "db", "db.sqlite3"),
         },
     }
     ```

   - **Static and Media Files**: Default paths for static and media files.
     ```python
     STATIC_ROOT = os.path.join(BASE_DIR, "apps/daggerboard_ui/static")
     STATIC_URL = "/static/"
     MEDIA_ROOT = os.path.join(BASE_DIR, "apps", "sbomscanner", "uploads")
     MEDIA_URL = "/uploads/"
     ```

   - **Logging**: Default log file paths.
     ```python
     SBOMPROCESS_LOGPATH = "/var/www/Daggerboard/logs/sbom.log"
     DAGGERBOARD_LOGPATH = "logs/daggerboard.log"
     CELERY_LOGPATH = "logs/celery.log"
     ```
#### Initial Authentication
---
The superuser is automatically configured during the installation process.


```
Username: admin
Password: ships&blades2024
```

For security reasons, please change the password immediately after your first login through the DaggerBoard Admin panel.




#### SBOM Upload Process

 ---

![Daggerboard Diagram](/.attachments/readme_db_diagram.png)


**User Provided Data**:
1. User uploads an SPDX or CycloneDX SBOM.
2. The SBOM is parsed and correlation is performed against the **local data object** for CPE.
   * If a match is found:
      * Retrieve the CVSS score.
      * Scrape ExploitDB for any exploits associated with the CVE. [https://www.exploit-db.com/]
      * Populate the Daggerboard database.
      * Notify the user of a successful upload.
   * If no match is found:
      * Perform a detailed search on the NVD website to match the CPE to the version.
      * If the detailed search finds a match:
         * Scrape ExploitDB for any exploits associated with the CVE. [https://www.exploit-db.com/]
         * Populate the Daggerboard database.
         * Notify the user of a successful upload.
      * If the detailed search does not find a match:
         * Generate a “Not Found” comment.
         * Populate the Daggerboard database.
         * Notify the user of a successful upload.


#### Grading Policy

---

Each severity level (critical, high, medium, low) is derived from the CVE assigned to a vulnerability, sourced from the NVD. This information is collected in a database and mapped to the respective packages from the SBOM based on CPE. The severities are counted and totaled, either at the vendor level or for individual SBOMs.

As part of our scoring system, we use multipliers (weights) assigned to each severity. These weights are set by default but can be configured in the admin settings.

- The count of Critical is multiplied by **40**
- The count of High is multiplied by **10**
- The count of Medium is multiplied by **3**
- The count of Low is multiplied by **1**

The **weighted sum** is the sum of the severities multiplied for a particular SBOM or vendor.

Final Grade = (**weighted sum**) / 54 (40 + 10 + 3 + 1)

Letter grade thresholds are set by default and can be configured in the admin settings:

- Final Grade <= 1: **A**
- Final Grade >= 2 and < 4: **B**
- Final Grade >= 4 and < 6: **C**
- Final Grade >= 6 and < 8: **D**
- Final Grade > 8: **F**


#### Authentication Using LDAP
---
Daggerboard supports LDAP authentication. To configure LDAP, add your LDAP settings within the Daggerboard admin panel under _Authentication and Authorization_. You will need to provide the following values related to your LDAP environment:
- **SERVER URI**: The server URI, starting with ldap:// or ldaps://
- **BIND DN**: The distinguished name of the authorized account in the LDAP directory tree
- **BIND PASSWORD**: The password for the BIND DN
- **USER SEARCH**: The object that locates a user in the directory
- **GROUP SEARCH**: The object that finds all LDAP groups that users might belong to
- **AUTH LDAP GROUP TYPE**: The instance describing the type of group returned by GROUP SEARCH
- **AUTH LDAP REQUIRE GROUP**: The distinguished name of a group; authentication will fail for any user that does not belong to this group

#### How to Contribute

---

All contributions are welcome!
Please take a moment to review the [DaggerBoard Contribution Guide](CONTRIBUTING.md).


#### Future Work

---
* Advanced reporting and analytics.
* Email and scheduled report options.
* Enhancements to SBOM search functionality to search by CVE.


#### Contributors

---

We would like to acknowledge the following individuals for their contributions to the Daggerboard project:

- **Adam Kojak**
- **Arlyn Sanchez**
- **Jay Benfield**
- **Katie Bratman**
- **Tony Vu**
- **Valton Hashani**
- **Will Landymore**

Their dedication and hard work have been instrumental in the development and success of this project.

#### License

---

This project is licensed under the terms of the [MIT license](LICENSE.md).


#### Release Notes

---
* Version 1.0.0 Initial  of DaggerBoard
* Version 2.0.0: Added API support and ported external scripts into the Django framework
