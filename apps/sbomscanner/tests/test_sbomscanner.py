import os
import sqlite3

import django
from django.test import Client


def test_convert_cyclonedx_to_spdx(create_cyclonedx_sbom):
    """Tests converstion of SBOM from cycloneDX to SPDX"""
    from apps.sbomscanner.packages.cyclonedx_to_spdx import XmlToSpdxConverter

    converter = XmlToSpdxConverter(
        upload_dir="/var/www/Daggerboard/apps/sbomscanner/uploads/sbom",
        archive="/archive_spdx",
    )
    converted_file_path = converter.convert()

    with open(converted_file_path, "r") as file:
        contents = file.read()

    # Check for specific SPDX tags in the file contents
    assert "SPDXVersion: SPDX-2.2" in contents
    assert "SPDXID: SPDXRef-DOCUMENT" in contents
    assert "PackageName: " in contents
    assert "PackageVersion: " in contents


def test_convert_json_to_spdx(create_json_sbom):
    """Tests conversion of SBOM from JSON to SPDX"""
    from apps.sbomscanner.packages.json_to_spdx import JsonToSpdxConverter

    converter = JsonToSpdxConverter()
    converted_files = converter.convert()

    # Assert that convert returns a list
    assert isinstance(converted_files, list)

    # Assert that the list is not empty
    assert len(converted_files) > 0

    # Assert that each item in the list is a dictionary with the expected keys
    for file in converted_files:
        assert isinstance(file, dict)
        assert "old_f" in file
        assert "new_f" in file
        assert "converted_f" in file
        assert "archive_path" in file


def test_apache_sbom_process(apache_spdx_file):
    from apps.sbomscanner.sbom_process import SbomScanner

    scan = SbomScanner()
    scan.main()


# Test for legacy sbom_process. Used for development comparisons
# def test_backup_apache_sbom_process(apache_spdx_file):
#     from sbomscanner.backup_sbom_process import main as backup_sbom_process
#     backup_sbom_process()


# create_random_spdx_sbom
def test_random_sbom_process(create_random_spdx_sbom):
    from apps.sbomscanner.sbom_process import SbomScanner

    scan = SbomScanner()
    scan.main()


# def test_backup_random_sbom_process(create_random_spdx_sbom):
#     from sbomscanner.backup_sbom_process import main as backup_sbom_process
#     backup_sbom_process()


def test_vulnerable_spdx_sbom(create_high_risk_spdx_sbom):
    from apps.sbomscanner.sbom_process import SbomScanner

    scan = SbomScanner()
    data = scan.main()
    letter_grade = (
        data.get("daggerboard_scorecard").get("sbomsummary_table").get("letter_grade")
    )
    assert letter_grade == "F", "Expected grade F for high risk SBOM"


def test_exploit_db():
    from apps.sbomscanner.packages.exploitdb_lookup import ExploitDBLookup

    exploit_db_lookup = ExploitDBLookup()
    list_of_vuln_cves = [
        "CVE-2014-0160",
        "CVE-2017-0144",
        "CVE-2011-4109",
        "CVE-2012-1823",
        "CVE-2018-8174",
        "CVE-2020-0601",
    ]
    for cve in list_of_vuln_cves:
        links = exploit_db_lookup.get_exploitdb_links(cve)
        assert isinstance(links, list)
        assert all(isinstance(link, str) for link in links)


def setup_module(module):
    os.environ["DJANGO_SETTINGS_MODULE"] = "daggerboardproject.settings.test"
    django.setup()


def test_sbom_scorecard():
    from apps.sbomscanner.packages.scorecard import ScorecardCalculations

    scorecard = ScorecardCalculations()
    data = scorecard.scorecardOverviewQueries(type="sbom", query_id="220")
    score = data["sbomsummary_table"].get("grade")
    assert score == 1


def test_letter_grade_calculation():
    from apps.sbomscanner.packages.scorecard import ScorecardCalculations

    scorecard = ScorecardCalculations()
    assert scorecard.get_letter_grade(1) == "A"
    assert scorecard.get_letter_grade(3) == "B"
    assert scorecard.get_letter_grade(5) == "C"
    assert scorecard.get_letter_grade(7) == "D"
    assert scorecard.get_letter_grade(9) == "F"


def test_get_latest_upload():
    """tests get_latest_upload function"""
    from apps.sbomscanner.sbom_process import SbomScanner

    conn = sqlite3.connect("db.sqlite3")
    sbomscanner = SbomScanner()
    latest_upload_id = sbomscanner.get_latest_upload(conn)
    assert latest_upload_id > 0


def test_sbom_scanner_letter_grade():
    from apps.sbomscanner.sbom_process import SbomScanner

    sbomscanner = SbomScanner()
    letter_grade = sbomscanner.get_letter_grade()
    assert letter_grade == "A"


def test_api_view():
    # Open an actual file for testing
    with open(
        os.path.join("apps", "sbomscanner", "tests", "sbom_samples", "apache.spdx"),
        "rb",
    ) as file:
        client = Client()
        response = client.post("/api/sbom/", {"file": file})
    # Check that the response status code is 200
    assert response.status_code == 200


def test_api_bearer_token(get_api_token):
    token = get_api_token
    assert token is not None


def test_token_based_sbom_upload(get_api_token):
    client = Client()
    response = client.post("/api/login/", {"username": "admin", "password": "password"})
    token = response.json().get("token")
    with open(
        os.path.join("apps", "sbomscanner", "tests", "sbom_samples", "apache.spdx"),
        "rb",
    ) as file:
        response = client.post(
            "/api/sbom/", {"file": file}, HTTP_AUTHORIZATION=f"Token {token}"
        )
    assert response.status_code == 200


def test_sbom_status(get_api_token):
    client = Client()
    response = client.post("/api/login/", {"username": "admin", "password": "password"})
    token = response.json().get("token")
    response = client.get(
        "/api/sbom/a141b3e7-e7cf-4d52-8d8d-198fd1e72ef3",
        HTTP_AUTHORIZATION=f"Token {token}",
    )
    assert response.status_code == 200
