import logging
import os
import re
import sys

from apps.sbomscanner.packages.file_hasher import FileHasher


class SPDXExtractor:
    def __init__(self, sbom_upload_directory, sbom_tags, sbom_doc_tags, ext):
        self.sbom_upload_directory = sbom_upload_directory
        self.sbom_tags = sbom_tags
        self.sbom_doc_tags = sbom_doc_tags
        self.ext = ext
        self.logger = logging.getLogger(__name__)
        self.package = []
        self.doc_tags = {}
        self.extract_spdx_details()

    def extract_spdx_details(self):
        """Extract package details from the SPDX file and document tags"""

        for fname in os.listdir(self.sbom_upload_directory):
            if fname.endswith(self.ext):
                self.fhash = FileHasher.calculate_hash(
                    self.sbom_upload_directory + "/" + fname
                )
                with open(
                    os.path.join(self.sbom_upload_directory, fname),
                    "r",
                    encoding="utf8",
                    errors="ignore",
                ) as f:
                    for line in f:
                        line = line.strip()
                        self.extract_doc_tags(line)
                        self.extract_package_tags(line)
        return self.package, self.doc_tags

    def extract_value(self, line, tag, clean=False):
        """Helper function for extract doc tags and package tags from SPDX file"""
        value = line.split(":", 1)[1] if clean else line.rsplit(":", 1)[1]
        value = value.strip()
        if clean:
            cleanrex = re.compile("<.*?>")
            value = re.sub(cleanrex, "", value)
        return value

    def extract_doc_tags(self, line):
        """
        Retrieve the following document tags from the SPDX file:
            'DocumentName:'
            'Creator: Organization:'
            'CreatorComment:'
        """
        for doc_tag in self.sbom_doc_tags:
            if doc_tag in line:
                self.doc_tags[doc_tag] = self.extract_value(
                    line, doc_tag, doc_tag == "CreatorComment:"
                )

    def extract_package_tags(self, line):
        """Extract package tags from SPDX file"""
        if "PackageName:" in line:
            pkg_items = {}
            self.package.append(pkg_items)

        if self.package:
            pkg_items = self.package[-1]
            for tag in self.sbom_tags:
                if tag in line:
                    self.logger.info(line)
                    if tag == "PackageName:":
                        value = line.rsplit(":", 1)[1].strip()
                        pkg_items[tag] = value
                    elif tag == "PackageComment:":
                        value = line.split(":", 1)[1]
                        value = re.sub(re.compile("<.*?>"), "", value).strip()
                        try:
                            pkg_items[tag] = value
                        except Exception:
                            self.handle_corrupted_file(self.fhash)
                    else:
                        value = line.rsplit(":", 1)[1].strip()
                        pkg_items[tag] = value

    def handle_corrupted_file(self, fhash):
        """Handle corrupted file"""
        for fl in os.listdir(self.sbom_upload_directory):
            msg = f"ERR-5-{fhash}: File {fl} is corrupted. Cannot be processed. Removing ..."
            self.logger.info(msg)
            os.remove(os.path.join(self.sbom_upload_directory, fl))
            sys.exit()
