# !/var/www/Daggerboard/venv/bin/python

import logging
import os
import random
import re
import shutil
import sqlite3
import string
import subprocess
import sys
import time
from pathlib import Path

from django.conf import settings

from apps.sbomscanner.packages.scorecard import ScorecardCalculations

from .packages.cyclonedx_to_spdx import XmlToSpdxConverter
from .packages.database_updater import DatabaseManager
from .packages.file_hasher import FileHasher
from .packages.json_to_spdx import JsonToSpdxConverter
from .packages.spdx_extractor import SPDXExtractor
from .packages.tag_validator import TagValidator

"""
Parses the SBOM for each package finds cpe and checks with nvd
results to see if theres a cve.
"""


class DotDict(dict):
    """Creates dot.notation access for dictionary attributes"""

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class SbomScanner:
    def __init__(self):
        self.basedir = os.getcwd()
        self.ext = ".spdx"
        self.basedirupload = os.getcwd()
        # Connect to  DB
        try:
            self.conn = sqlite3.connect(Path(settings.BASE_DIR, "db", "db.sqlite3"))
        except Exception as e:
            logging.error("Error connecting to sqlite Platform: {}".format(e))
            sys.exit(1)

    def writelog(self, msg):
        with open(self.logfile, "a+") as logger:
            logger.write(self.now + " " + msg + "\n")

    def stripHash(self, line):
        """Remove lines with hash (commented lines) in the front"""
        line = str(line)
        return re.sub(r"(?m)^ *#.*\n?", "", line)

    def log_and_exit_bad_file(self, fname, line_number):
        msg = f"Bad file {os.path.join(self.sbom_upload_directory, fname)} at line nr: {line_number}"
        self.writelog(msg)
        exit()

    def log_missing_tag(self, fhash, tag, fname, tag_count):
        msg = f"INFO-00-{fhash}: Tag '{tag}' is missing in file '{fname}', {tag_count} occurrences. Fixed."
        self.writelog(msg)

    def validate_spdx_isTagEmpty(self):
        """Validate if the SPDX tags are empty"""
        for fname in os.listdir(self.sbom_upload_directory):
            if fname.endswith(self.ext):
                with open(
                    os.path.join(self.sbom_upload_directory, fname),
                    "r",
                    encoding="utf8",
                    errors="ignore",
                ) as f:
                    for line_number, line in enumerate(f, start=1):
                        for tag in self.sbom_tags:
                            if tag in line:
                                line_content = line.rsplit(":", 1)[1].strip()
                                if line_content == "":
                                    self.log_and_exit_bad_file(fname, line_number)

    def remove_file_with_log(self, fname, fhash, error_code, reason):
        msg = f"{error_code}-{fhash}: Removing {fname}. {reason}."
        self.writelog(msg)
        os.remove(os.path.join(self.sbom_upload_directory, fname))
        exit()

    def check_sha1_in_db(self, sbom_upload_directory, ext):
        """Check if the SHA1 hash of a file exists in the database"""
        if os.listdir(sbom_upload_directory)[0].endswith(ext):
            target_file = os.listdir(sbom_upload_directory)[0]
            sha1 = FileHasher.calculate_hash(
                os.path.join(sbom_upload_directory, target_file)
            )

            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT filehash from daggerboard_sbom WHERE filehash = ?", (sha1,)
            )
            db_result = cursor.fetchall()

            if db_result:
                self.writelog(
                    f"INFO-1-{sha1}: File with SHA1 hash {sha1} already in database."
                )
                # return True
        return False

    def get_latest_upload(self):
        """Get the latest upload time and return the corresponding id."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id
            FROM daggerboard_sbom
            ORDER BY uploadtime DESC
            LIMIT 1
            """
        )
        db_result = cursor.fetchone()
        return db_result[0] if db_result else None

    def get_scorecard_data(self):
        latest_id = self.get_latest_upload()
        scorecard = ScorecardCalculations()
        scorecard_data = scorecard.scorecardOverviewQueries("sbom", latest_id)
        return scorecard_data

    def execute_command_on_nvd_repo(self, package_version, cpedict, srchstr):
        """Testing if the spdx package name and version are found in a cpe dictionary"""
        cmd = f'grep -iF ":{package_version}:" {cpedict} | grep -iF "{srchstr}" | grep -iv "for android"'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        return process.stdout.readline()

    def process_pn(self, package_name, delimiter):
        package_name = package_name.replace("microsoft", "").strip()
        if len(package_name.replace(delimiter, " ").split()) > 1:
            srchstr = package_name.replace(delimiter, " ").split()
            srchstr = delimiter.join(srchstr[:2])
            return srchstr
        return None

    def execute_command(self, cmd):
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        return proc.stdout.readline().rstrip().decode("utf-8")

    def process_cperesult(self, cperesult):
        cpeoutter = {"cpe": {"cpe": cperesult}}
        return cpeoutter

    def process_ln(self, ln):
        # cve, cve_sum, cve_score, cve_severity, cve_vector = ln.split("|")
        cve = ln.split("|")[0]
        cve_sum = ln.split("|")[1]
        cve_score = ln.split("|")[2]
        cve_severity = ln.split("|")[3]
        cve_vector = ln.split("|")[4]

        cvelocal = {
            "cve_out": cve,
            "cve_sum_out": cve_sum,
            "cve_score_out": cve_score,
            "cve_severity_out": cve_severity,
            "cve_vector_out": cve_vector,
        }
        cvelocaloutter = {"cve": [cvelocal]}
        return cvelocaloutter

    def process_no_cperesult(self):
        cpeoutter = {"cpe": {"cpe": "CPE Not Found"}}
        cvelocaloutter = {
            "cve": [
                {
                    "cve_out": "na",
                    "cve_sum_out": "na",
                    "cve_score_out": "na",
                    "cve_severity_out": "na",
                    "cve_vector_out": "na",
                }
            ]
        }
        return cpeoutter, cvelocaloutter

    def insert_into_table(self, query, data):
        cursor = self.conn.cursor()
        cursor.execute(query, data)
        last_row_id = cursor.lastrowid
        self.conn.commit()
        return last_row_id

    # TODO - Refactor this method too complex
    def main(self):  # noqa
        self.spdx_basedir = settings.DAGGERBOARD_BASEDIR
        self.sbom_upload_directory = settings.UPLOAD_DIRECTORY
        self.proxy = settings.PROXY_URL

        self.cvefile = os.path.join(self.spdx_basedir, "nvdrepo/nvdcvecpe.csv")
        self.cpedict = os.path.join(self.spdx_basedir, "nvdrepo/nvdcpedict.csv")
        self.logfile = os.path.join(settings.BASE_DIR, "sbom.log")
        self.archive_spdx_dir = os.path.join(
            settings.BASE_DIR, "apps", "sbomscanner", "archive_spdx"
        )
        self.now = time.strftime("%Y-%m-%d %H:%M:%S")

        depth_level = 3

        # Convert cyclonedx to spdx format
        for filename in os.listdir(self.sbom_upload_directory):
            file_path = Path(self.sbom_upload_directory) / filename
            if file_path.suffix == ".xml":
                xmlconverter = XmlToSpdxConverter(
                    upload_dir=self.sbom_upload_directory,
                    archive="/archive_spdx",
                )
                xmlconverter.convert()

        # Convert json to spdx format
        for filename in os.listdir(self.sbom_upload_directory):
            file_path = Path(self.sbom_upload_directory) / filename
            if file_path.suffix == ".xml":
                jsonconverter = JsonToSpdxConverter()
                jsonconverter.convert()

        # Check if the SHA1 hash of the file has already been processed
        is_sha1_in_db = self.check_sha1_in_db(self.sbom_upload_directory, self.ext)
        if is_sha1_in_db:
            self.writelog("SHA1 hash of the file is already in the database.")

        # ProductName and VendorName are extra attributes
        self.sbom_doc_tags = [
            "DocumentName:",
            "Creator: Organization:",
            "CreatorComment:",
        ]
        self.sbom_tags = [
            "PackageName:",
            "PackageVersion:",
            "PackageSupplier: Organization:",
            "PackageComment:",
        ]

        # Validate SPDX file
        TagValidator(
            self.sbom_upload_directory, self.sbom_tags, self.sbom_doc_tags, self.ext
        )
        self.validate_spdx_isTagEmpty()

        spdx_extracted_results = SPDXExtractor(
            self.sbom_upload_directory, self.sbom_tags, self.sbom_doc_tags, self.ext
        )
        package = spdx_extracted_results.package
        doc_tags = spdx_extracted_results.doc_tags

        # Remove dictionary if the key contains SPDXRef
        packages = [
            package_record
            for package_record in package
            if not ("SPDXRef" in package_record["PackageName:"])
        ]

        mainlist = []
        for package_record in range(len(packages)):
            try:
                logging.info(f"starting scan on {str(packages[package_record])}")
                pno = packages[package_record]["PackageName:"].lower()
                pvo = packages[package_record]["PackageVersion:"].lower()
                psup = packages[package_record].get("PackageSupplier: Organization:")
                pcom = packages[package_record].get("PackageComment:")
            except Exception as e:
                logging.info(e)
                for fl in os.listdir(self.sbom_upload_directory):
                    # Get SHA1 hash for log tracking
                    self.fhash = FileHasher.calculate_hash(
                        self.sbom_upload_directory + "/" + fl
                    )
                    # When package_record stanzas are not standardized exit and remove the file
                    msg = "ERR-5-{}: File {} is corrupted. Cannot be processed. See #{}. Removing ...".format(
                        self.fhash, fl, packages[package_record]
                    )
                    self.writelog(msg)
                    os.remove(os.path.join(self.sbom_upload_directory, fl))
                    sys.exit()

            # for DB / packages table
            mainperpkg = []
            pkgmain = {}
            pkgitemdct = {}

            pkgitemdct["PackageName:"] = pno
            pkgitemdct["PackageVersion:"] = pvo
            pkgitemdct["PackageSupplier: Organization:"] = psup
            pkgitemdct["PackageComment:"] = pcom
            pkgmain["pkg"] = pkgitemdct

            mainperpkg.append(pkgmain)

            package_name = packages[package_record]["PackageName:"].lower()
            package_version = packages[package_record]["PackageVersion:"].lower()
            # Parsing different cases of PackageName
            # Make the search greedy by removing last char, just in case, but still trying to get results
            if "libcurl" in package_name:
                package_name = package_name[:-1]
            if "libacl" in package_name:
                package_name = package_name[:-1]
            if "libattr" in package_name:
                package_name = package_name[:-1]
            if "libssl" in package_name:
                package_name = "libssl"
            if "libcrypto" in package_name:
                package_name = "libcrypto"
            if "libusb" in package_name:
                package_name = "libusb"
            if "libpixman" in package_name:
                package_name = "libpixman"
            if "c++" in package_name:
                package_name = package_name.replace("++", "\+\+")  # noqa

            # Parsing PackageVersion
            # Get everything before word ubuntu.
            # This will return 3.28.3-0 from 3.28.3-0ubuntu1~18.04.1
            if "ubuntu" in package_version:
                package_version = re.sub("[-_+~]", " ", package_version)
                package_version = package_version.split("ubuntu", 1)[0].split()[0]

            package_version = re.sub("[-_+~]", " ", package_version).split()[0]

            # Match versions if in format 1.0.2q.iv.2.0
            pvrex = re.compile("^(\d+\.?)+")  # noqa
            match = pvrex.match(package_version)
            if match:
                package_version = match.group(0).strip()
            else:
                package_version = None

            if package_version and package_version.endswith("."):
                package_version = package_version[:-1]

            cperesult = self.execute_command_on_nvd_repo(
                package_version, self.cpedict, package_name
            )

            package_name = package_name.replace("microsoft", "").strip()
            for delimiter in ["_", "-"]:
                srchstr = self.process_pn(package_name, delimiter)
                if srchstr:
                    cperesult = self.execute_command_on_nvd_repo(
                        package_version, self.cpedict, srchstr
                    )
                    if cperesult:
                        break

            if not cperesult:
                package_name = package_name.replace("_", " ").replace("-", " ").strip()
                g = "grep -iF "
                s = ""
                if len(package_name.split()) > 1:
                    wordlist = package_name.split()[:depth_level]
                    for k in wordlist:
                        s += g + '"' + k + '"' + "|"
                    if s.endswith("|"):
                        s = s[:-1]
                    if package_version and package_version.endswith("."):
                        package_version = package_version[:-1]
                    cmd = f'grep -iF ":{package_version}:" {self.cpedict} | {s} | grep -iv "for android"'
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                    cperesult = process.stdout.readline()

            if cperesult:
                cperesult = cperesult.rstrip().decode("utf-8").split("|")[1].strip()
                cpeoutter = self.process_cperesult(cperesult)
                mainperpkg.append(cpeoutter)

                # Find CVEs locally
                cmd = f'grep -iF "{cperesult}" {self.cvefile}'
                ln = self.execute_command(cmd)

                if ln != "":
                    logging.info("LOCAL: ", ln)
                    cvelocaloutter = self.process_ln(ln)
                    mainperpkg.append(cvelocaloutter)
            else:
                cpeoutter, cvelocaloutter = self.process_no_cperesult()
                mainperpkg.extend([cpeoutter, cvelocaloutter])

            mainlist.append(mainperpkg)

        try:
            documentname = doc_tags.get("DocumentName:", "")
            creatororganization = doc_tags.get("Creator: Organization:", "")
            creatorcomment = doc_tags.get("CreatorComment:", "")
        except Exception as e:
            logging.info(e)

        if not documentname or not creatororganization or not creatorcomment:
            logging.info(
                "Error: missing DocumentName, Creator: Organization, or CreatorComment"
            )
            logging.info("Error: ", doc_tags)
            sys.exit(1)

        DatabaseManager(
            self.conn,
            mainlist,
            self.sbom_upload_directory,
            documentname,
            creatororganization,
            creatorcomment,
            self.now,
        )

        try:
            for fname in os.listdir(self.sbom_upload_directory):
                fhash = FileHasher.calculate_hash(
                    self.sbom_upload_directory + "/" + fname
                )
                msg = "INFO-1-{}: Processing of file {} is complete.".format(
                    fhash, fname
                )
                self.writelog(msg)
                random_suffix = "".join(
                    random.choice(string.ascii_letters) for i in range(4)
                )
                shutil.move(
                    os.path.join(self.sbom_upload_directory, fname),
                    os.path.join(self.archive_spdx_dir, fname + "." + random_suffix),
                )
        except shutil.Error as e:
            logging.info(e)
            logging.info("File {} already in archive".format(fname))

        scorecard_data = DotDict(self.get_scorecard_data())
        self.conn.close()
        return {"daggerboard_scorecard": scorecard_data}
