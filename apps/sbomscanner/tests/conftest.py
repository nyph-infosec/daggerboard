import glob
import os
import random
import time
from pathlib import Path

import pytest
from django.test import Client

basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def create_cyclonedx_sbom():
    content = """<?xml version="1.0" encoding="UTF-8"?>
  <bom xmlns="http://cyclonedx.org/schema/bom/1.3" version="1">
    <components>
      <component type="library" bom-ref="pkg:npm/jquery@3.5.1">
        <name>jquery</name>
        <version>3.5.1</version>
        <purl>pkg:npm/jquery@3.5.1</purl>
        <hashes>
          <hash alg="SHA-256">6ddcceac8f8c5ee6f6c33e8e4f035c3d99f0f59f41a6b36d2298a4b5e6a04f98</hash>
        </hashes>
        <licenses>
          <license>
            <id>MIT</id>
          </license>
        </licenses>
      </component>
    </components>
  </bom>"""

    upload_dir = "/var/www/Daggerboard/apps/sbomscanner/uploads/sbom"
    cyclonedx_file = Path(upload_dir, "bom.xml")
    cyclonedx_file.write_text(content)

    try:
        yield str(cyclonedx_file)
    finally:
        spdx_files = Path(upload_dir, "bom.spdx")
        if os.path.exists(str(cyclonedx_file)):
            os.remove(str(cyclonedx_file))
        if os.path.exists(str(spdx_files)):
            os.remove(str(spdx_files))


@pytest.fixture
def create_json_sbom():
    content = """{
    "name": "Sample Project",
    "spdxVersion": "SPDX-2.2",
    "SPDXID": "SPDXRef-DOCUMENT",
    "creationInfo": {
        "creators": ["Organization: ExampleOrg"],
        "created": "2020-01-01T00:00:00Z"
    },
    "packages": [
        {
        "name": "package1",
        "versionInfo": "1.0.0",
        "sourceInfo": "https://example.com/package1",
        "SPDXID": "SPDXRef-Package-1"
        },
        {
        "name": "package2",
        "versionInfo": "2.0.0",
        "sourceInfo": "https://example.com/package2",
        "SPDXID": "SPDXRef-Package-2"
        }
    ]
    }"""
    upload_dir = "/var/www/Daggerboard/apps/sbomscanner/uploads/sbom"
    json_file = Path(upload_dir, "bom.json")
    json_file.write_text(content)
    yield str(json_file)
    files_to_remove = glob.glob(os.path.join(upload_dir, "*.spdx"))
    for file in files_to_remove:
        os.remove(file)


@pytest.fixture
def create_spdx_sbom():
    content = """SPDXVersion: SPDX-2.2
DocumentName: SPDXRef-DOCUMENT
SPDXID: SPDXRef-DOCUMENT
Creator: Tool: SPDX-Tools_v2.2.3
Created: 2020-07-23T18:30:22Z
PackageName: Sample Project
PackageVersion: 1.0
PackageDownloadLocation: NONE
FilesAnalyzed: false
PackageChecksum: SHA256: 2cab619b7b7ee2e69a83b0ef810c9fdbc37222eac4e4a310f6b3b653b2f702fb
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageLicenseComments: A sample project
PackageSPDXIdentifier: SPDXRef-Package"""

    upload_dir = "/var/www/Daggerboard/apps/sbomscanner/uploads/sbom"
    spdx_file = Path(upload_dir, "bom.spdx")
    spdx_file.write_text(content)

    try:
        yield str(spdx_file)
    finally:
        if spdx_file.exists():
            spdx_file.unlink()


@pytest.fixture
def create_random_spdx_sbom():
    content = f"""SPDXVersion: SPDX-2.2
DocumentName: SPDXRef-DOCUMENT
SPDXID: SPDXRef-DOCUMENT
Creator: Tool: SPDX-Tools_v2.2.3
Created: {time.ctime()}
PackageName: Sample Project
PackageVersion: {random.randint(1, 100)}
PackageDownloadLocation: NONE
FilesAnalyzed: false
PackageChecksum: SHA256: 2cab619b7b7ee2e69a83b0ef810c9fdbc37222eac4e4a310f6b3b653b2f702fb
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageLicenseComments: A sample project
PackageSPDXIdentifier: SPDXRef-Package"""

    upload_dir = "/var/www/Daggerboard/apps/sbomscanner/uploads/sbom"
    spdx_file = Path(upload_dir, "bom.spdx")
    spdx_file.write_text(content)

    try:
        yield str(spdx_file)
    finally:
        if spdx_file.exists():
            spdx_file.unlink()


@pytest.fixture
def apache_spdx_file():
    # Specify the path to your SPDX file
    spdx_file_path = "apps/sbomscanner/tests/sbom_samples/apache.spdx"

    # Open the file and read its contents
    with open(spdx_file_path, "r") as file:
        spdx_content = file.read()

    upload_dir = "/var/www/Daggerboard/apps/sbomscanner/uploads/sbom"
    spdx_file = Path(upload_dir, "apache.spdx")
    spdx_file.write_text(spdx_content)

    try:
        yield str(spdx_file)
    finally:
        if spdx_file.exists():
            spdx_file.unlink()


@pytest.fixture
def create_high_risk_spdx_sbom():
    content = f"""SPDXVersion: SPDX-2.2
    DocumentName: SPDXRef-DOCUMENT
    SPDXID: SPDXRef-DOCUMENT
    Creator: Tool: SPDX-Tools_v2.2.3
    Created: {time.ctime()}
    PackageName: libxml2
    PackageSupplier: Organization: GNOME
    PackageComment: Known vulnerable package
    SPDXID: SPDXRef-Package-libxml2
    PackageVersion: 2.9.1
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageLicenseConcluded: MIT
    PackageLicenseDeclared: MIT
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:xmlsoft:libxml2:2.9.1:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:xmlsoft/libxml2@2.9.1

    PackageName: openssl
    PackageSupplier: Organization: OpenSSL Project
    PackageComment: Known vulnerable package
    SPDXID: SPDXRef-Package-openssl
    PackageVersion: 1.0.1f
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageLicenseConcluded: OpenSSL
    PackageLicenseDeclared: OpenSSL
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:openssl/openssl@1.0.1f

    PackageName: apache-http-server
    SPDXID: SPDXRef-Package-apache-http-server
    PackageVersion: 2.2.15
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: Apache-2.0
    PackageLicenseDeclared: Apache-2.0
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:apache:http_server:2.2.15:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:apache/http_server@2.2.15

    PackageName: nginx
    SPDXID: SPDXRef-Package-nginx
    PackageVersion: 1.4.0
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: BSD-2-Clause
    PackageLicenseDeclared: BSD-2-Clause
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:nginx:nginx:1.4.0:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:nginx/nginx@1.4.0

    PackageName: mysql
    SPDXID: SPDXRef-Package-mysql
    PackageVersion: 5.1.73
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: GPL-2.0-only
    PackageLicenseDeclared: GPL-2.0-only
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:mysql:mysql:5.1.73:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:mysql/mysql@5.1.73

    PackageName: php
    SPDXID: SPDXRef-Package-php
    PackageVersion: 5.3.29
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: PHP-3.01
    PackageLicenseDeclared: PHP-3.01
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:php:php:5.3.29:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:php/php@5.3.29

    PackageName: jquery
    SPDXID: SPDXRef-Package-jquery
    PackageVersion: 1.6.1
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: MIT
    PackageLicenseDeclared: MIT
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:jquery:jquery:1.6.1:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:jquery/jquery@1.6.1

    PackageName: bootstrap
    SPDXID: SPDXRef-Package-bootstrap
    PackageVersion: 3.3.5
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: MIT
    PackageLicenseDeclared: MIT
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:twbs:bootstrap:3.3.5:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:twbs/bootstrap@3.3.5

    PackageName: struts
    SPDXID: SPDXRef-Package-struts
    PackageVersion: 2.3.16.1
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: Apache-2.0
    PackageLicenseDeclared: Apache-2.0
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:apache:struts:2.3.16.1:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:apache/struts@2.3.16.1

    PackageName: tomcat
    SPDXID: SPDXRef-Package-tomcat
    PackageVersion: 7.0.54
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageVerificationCode: NOASSERTION
    PackageLicenseConcluded: Apache-2.0
    PackageLicenseDeclared: Apache-2.0
    PackageLicenseComments: NOASSERTION
    PackageCopyrightText: NOASSERTION
    ExternalRef: SECURITY cpe23Type cpe:2.3:a:apache:tomcat:7.0.54:*:*:*:*:*:*:*
    ExternalRef: PACKAGE_MANAGER purl pkg:apache/tomcat@7.0.54"""
    upload_dir = "/var/www/Daggerboard/apps/sbomscanner/uploads/sbom"
    spdx_file = Path(upload_dir, "bom.spdx")
    spdx_file.write_text(content)

    try:
        yield str(spdx_file)
    finally:
        if spdx_file.exists():
            spdx_file.unlink()


@pytest.fixture
def get_api_token():
    client = Client()
    credentials = {"username": "admin", "password": "password"}
    response = client.post("/api/login/", data=credentials)
    token = response.json().get("token")
    return token
