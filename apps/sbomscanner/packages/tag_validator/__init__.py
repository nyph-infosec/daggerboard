import logging
import os
import re

from apps.sbomscanner.packages.file_hasher import FileHasher


class TagValidator:
    def __init__(self, sbom_upload_directory, sbom_tags, sbom_doc_tags, ext):
        self.sbom_upload_directory = sbom_upload_directory
        self.sbom_tags = sbom_tags
        self.sbom_doc_tags = sbom_doc_tags
        self.ext = ext
        self.logger = logging.getLogger(__name__)
        self.doc_taglist = []
        self.taglist = []
        self.validate_spdx_ifTagExists()

    def stripHash(self, line):
        """Remove lines with hash (commented lines) in the front"""
        line = str(line)
        return re.sub(r"(?m)^ *#.*\n?", "", line)

    def validate_spdx_ifTagExists(self):
        for fname in os.listdir(self.sbom_upload_directory):
            if fname.endswith(self.ext):
                self.process_sbom_file(fname)

    def process_sbom_file(self, fname):
        fhash = FileHasher.calculate_hash(self.sbom_upload_directory + "/" + fname)
        with open(
            os.path.join(self.sbom_upload_directory, fname), "r+", encoding="utf8"
        ) as sbom_file:
            data = sbom_file.read()

            self.check_package_name_tag(fname, fhash, data)
            self.check_document_tags(fname, fhash, data)
            self.check_sbom_tags(fname, fhash, data)

            sbom_file.seek(0)
            file_content = self.strip_hash_and_get_content(fname, sbom_file)

            sbom_file.seek(0)
            self.update_sbom_file(sbom_file, file_content)

    def check_package_name_tag(self, fname, fhash, data):
        package_name_occurrence = data.count("PackageName:")
        if package_name_occurrence == 0:
            self.logger.info(
                f'fname: {fname}, fhash: {fhash}, "ERR-3", "PackageName tag missing"'
            )

    def check_document_tags(self, fname, fhash, data):
        for doc_tag in self.sbom_doc_tags:
            doc_tag_count = data.count(doc_tag)
            if doc_tag_count == 0:
                self.doc_taglist.append(doc_tag)
                self.logger.info(
                    f"fhash: {fhash}, doc_tag: {doc_tag}, fname: {fname}, doc_tag_count: {doc_tag_count}"
                )

    def check_sbom_tags(self, fname, fhash, data):
        package_name_occurrence = data.count("PackageName:")
        for tag in self.sbom_tags:
            tag_count = data.count(tag)
            if tag_count != package_name_occurrence:
                self.taglist.append(tag)
                self.logger.info(
                    f"fhash: {fhash}, tag: {tag}, fname: {fname}, tag_count: {tag_count}"
                )

        if "PackageVersion:" in self.taglist:
            self.logger.info(f'fname: {fname}, fhash: {fhash} "ERR-4", "Corrupt file"')

    def strip_hash_and_get_content(self, fname, sbom_file):
        file_content = []
        for line in sbom_file:
            line = self.stripHash(line.rstrip())
            file_content.append(line)

            if "SPDXVersion:" in line:
                for document_tag in self.doc_taglist:
                    file_content.append(document_tag + " " + fname.split(self.ext)[0])

            if "PackageName:" in line:
                for tg in self.taglist:
                    file_content.append(tg + " tag_fixed")

        return file_content

    def update_sbom_file(self, sbom_file, file_content):
        for tag in file_content:
            sbom_file.write(tag + "\n")
