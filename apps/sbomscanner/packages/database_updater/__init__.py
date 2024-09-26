import logging
import os

from apps.sbomscanner.packages.exploitdb_lookup import ExploitDBLookup
from apps.sbomscanner.packages.file_hasher import FileHasher

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(
        self,
        conn,
        mainlist,
        sbom_upload_directory,
        documentname,
        creatororganization,
        creatorcomment,
        now,
    ):
        self.conn = conn
        self.cursor = conn.cursor()
        self.sbom_upload_directory = sbom_upload_directory
        self.exploit_lookup = ExploitDBLookup()
        sbom_lrowid = self.insert_sbom(
            documentname, creatororganization, creatorcomment, now
        )
        try:
            self.process_mainlist(conn, mainlist, sbom_lrowid)
        except Exception as e:
            logger.error(e)
            if self.conn:
                self.conn.rollback()

    def get_cve_exploit(self, cve):
        exploit_list = []
        escriptres = self.exploit_lookup.get_exploitdb_links(cve)
        for url in escriptres:
            exploit_list.append(url.strip())
        cve_exploit = "|".join(exploit_list)
        return cve_exploit if cve_exploit else "exploit_not_found"

    def insert_into_table(self, query, data):
        self.cursor.execute(query, data)
        last_row_id = self.cursor.lastrowid
        self.conn.commit()
        return last_row_id

    def process_package(self, conn, sbom_lrowid, v):
        self.packages_lrowid = self.insert_package(conn, sbom_lrowid, v)

    def process_cpe(self, conn, sbom_lrowid, packages_lrowid, v):
        self.cpes_lrowid = self.insert_cpe(conn, sbom_lrowid, packages_lrowid, v)

    def process_mainlist(self, conn, mainlist, sbom_lrowid):
        for pkgs in mainlist:
            for i in pkgs:
                for k, v in i.items():
                    if isinstance(v, dict):
                        if "pkg" in k:
                            self.process_package(conn, sbom_lrowid, v)
                        if "cpe" in k:
                            self.process_cpe(conn, sbom_lrowid, self.packages_lrowid, v)
                    if isinstance(v, list):
                        if "cve" in k:
                            self.insert_cve(
                                conn,
                                self.cpes_lrowid,
                                self.packages_lrowid,
                                sbom_lrowid,
                                v,
                            )

    def insert_package(self, conn, sbom_lrowid, v):
        return self.insert_into_table(
            "INSERT INTO daggerboard_package (sbomid_packages, packagename, packageversion, packagesupplier, packagecomment) VALUES (?,?,?,?,?)",
            (
                sbom_lrowid,
                v["PackageName:"],
                v["PackageVersion:"],
                v["PackageSupplier: Organization:"],
                v["PackageComment:"],
            ),
        )

    def insert_cpe(self, conn, sbom_lrowid, packages_lrowid, v):
        return self.insert_into_table(
            "INSERT INTO daggerboard_cpe (sbomid_cpe, packageid_cpe, cpe) VALUES (?,?,?)",
            (sbom_lrowid, packages_lrowid, v["cpe"]),
        )

    def insert_cve(
        self, conn, cpes_lrowid, packages_lrowid, sbom_lrowid, vulnerabilities
    ):
        query = """
        INSERT INTO daggerboard_cve
        (cpeid_cve, packageid_cve, sbomid_cve, cve, cve_sum, cvss3_score, cvss3_severity, cvss3_vector, cve_exploit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        for vulnerability in vulnerabilities:
            cve_exploit = self.get_cve_exploit(vulnerability["cve_out"])
            cve_sum_out = vulnerability.get("cve_sum_out", "na")
            cve_score_out = vulnerability.get("cve_score_out", "na")
            cve_severity_out = vulnerability.get("cve_severity_out", "na")
            cve_vector_out = vulnerability.get("cve_vector_out", "na")
            data = (
                cpes_lrowid,
                packages_lrowid,
                sbom_lrowid,
                cve_exploit,
                cve_sum_out,
                cve_score_out,
                cve_severity_out,
                cve_vector_out,
                cve_exploit,
            )
            self.insert_into_table(query, data)

    def sbom_exists(self, fhash):
        """Check if record exists in the daggerboard_sbom table
        This is used to prevent duplicate entries in the WebApp
        Dashboard table.
        """
        query = "SELECT 1 FROM daggerboard_sbom WHERE filehash = ?"
        self.cursor.execute(query, (fhash,))
        return self.cursor.fetchone() is not None

    def sbom_get_last_row_id(self, fhash):
        """Check if record exists in the daggerboard_sbom table
        This is used to prevent duplicate entries in the WebApp
        Dashboard table.
        """
        query = "SELECT id FROM daggerboard_sbom WHERE filehash = ?"
        self.cursor.execute(query, (fhash,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def insert_sbom(self, documentname, creatororganization, creatorcomment, now):
        query = """
        INSERT INTO daggerboard_sbom
        (documentname, vendorname, creatororganization, creatorcomment, uploadtime, modtime, filehash)
        VALUES (?,?,?,?,?,?,?)
        """
        for fname in os.listdir(self.sbom_upload_directory):
            fhash = FileHasher.calculate_hash(self.sbom_upload_directory + "/" + fname)
            if not self.sbom_exists(fhash):
                data = (
                    documentname,
                    creatororganization,
                    creatororganization,
                    creatorcomment,
                    now,
                    now,
                    fhash,
                )
                sbom_lrowid = self.insert_into_table(query, data)
            else:
                sbom_lrowid = self.sbom_get_last_row_id(fhash)
            return sbom_lrowid
