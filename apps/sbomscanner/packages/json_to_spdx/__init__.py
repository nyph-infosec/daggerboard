import json
import logging
import os
import re
import shutil
from pathlib import Path

from django.conf import settings


class JsonToSpdxConverter:
    def __init__(self):
        self.basedir = os.getcwd()
        self.upload_dir = settings.UPLOAD_DIRECTORY
        self.archive = settings.ARCHIVE_PATH

    def convert(self):
        """Convert JSON files to SPDX files"""
        self.converted = list()
        for file in os.listdir(self.upload_dir):
            logging.info(f"found file {file}")
            in_file_path = Path(self.upload_dir, file)
            if os.path.isfile(in_file_path) and file.endswith(".json"):
                logging.info("[+] Confirmed JSON file, starting parsing...")
                converted_file = self.parse_json(in_file_path, file)
                self.converted.append(converted_file)
        return self.converted

    def parse_json(self, in_file_path, file):
        with open(in_file_path, "r") as original_json:
            try:
                to_parse_json = json.load(original_json)
                doc_name, spdx_fn = self.get_document_name(to_parse_json, file)
                spdx_version = self.get_spdx_version(to_parse_json)
                spdx_id = self.get_spdx_id(to_parse_json)
                org = self.get_org(to_parse_json)
                pkg_to_add = self.get_packages(to_parse_json)
                converted_spdx_fn = self.write_to_spdx_file(
                    doc_name, org, pkg_to_add, spdx_fn, spdx_id, spdx_version
                )
                archive_path = self.move_to_archive(file, in_file_path)
                logging.info(f"CONVERTED from JSON to SPDX_tag_value: {file} {spdx_fn}")
                return {
                    "old_f": file,
                    "new_f": spdx_fn,
                    "converted_f": converted_spdx_fn,
                    "archive_path": archive_path,
                }
            except Exception as e:
                logging.info(
                    "ERR: .JSON"
                    + file
                    + "file not in JSON format, skipping. Error:"
                    + e
                )
                return None

    def get_document_name(self, to_parse_json, file):
        try:
            doc_name = to_parse_json["name"]
        except KeyError:
            doc_name = file
        doc_name = re.sub("[.:]", "_", doc_name)
        spdx_name = "".join(re.split("[^a-zA-Z0-9_]*", doc_name))
        spdx_fn = Path(self.upload_dir, spdx_name + "_converted.spdx")
        return doc_name, spdx_fn

    def get_spdx_version(self, to_parse_json):
        try:
            return to_parse_json["spdxVersion"]
        except KeyError:
            return "SPDX-2.2"

    def get_spdx_id(self, to_parse_json):
        try:
            return to_parse_json["SPDXID"]
        except KeyError:
            return "SPDXRef-DOCUMENT"

    def get_org(self, to_parse_json):
        try:
            org_parse = to_parse_json["creationInfo"]["creators"]
            logging.info(f"Org parse val: {org_parse}")
            return org_parse[0].split(":")[1]
        except KeyError:
            return ""

    def get_packages(self, to_parse_json):
        pkg_to_add = []
        for package in to_parse_json.get("packages", []):
            pkg_to_add.append(
                {
                    "pkg_name": package.get("name", ""),
                    "pkg_vers": package.get("versionInfo", ""),
                    "pkg_comment": package.get("sourceInfo", ""),
                }
            )
        return pkg_to_add

    def write_to_spdx_file(
        self, doc_name, org, pkg_to_add, spdx_fn, spdx_id, spdx_version
    ):
        converted_spdx_fn = Path(self.upload_dir, spdx_fn)
        with open(converted_spdx_fn, "w") as new_spdx_f:
            new_spdx_f.write("SPFXVersion: " + spdx_version + "\n")
            new_spdx_f.write("SPDXID: " + spdx_id + "\n")
            new_spdx_f.write("DocumentName: " + doc_name + "\n")
            new_spdx_f.write("Creator: Organization: " + org + "\n")
            new_spdx_f.write('CreatorComment: "" \n')
            for pkg_val in pkg_to_add:
                new_spdx_f.write(
                    "\n"
                    + "PackageName: "
                    + pkg_val["pkg_name"]
                    + "\nPackageVersion: "
                    + pkg_val["pkg_vers"]
                    + "\nPackageComment: "
                    + pkg_val["pkg_comment"]
                    + "\n"
                )
        return converted_spdx_fn

    def move_to_archive(self, file, in_file_path):
        archive_path = Path(self.archive, file)
        shutil.move(in_file_path, archive_path)
        return archive_path
