import hashlib
from datetime import date

import environ
import pyaes
from django.db import models
from django.utils import timezone

env = environ.Env()
environ.Env.read_env()


class Sbom(models.Model):
    """
    Model for holding data specific to SBOMs uploaded.
    """

    id = models.AutoField(primary_key=True)
    documentname = models.CharField(max_length=200)
    vendorname = models.CharField(max_length=100)
    productname = models.CharField(max_length=100)
    creatororganization = models.CharField(max_length=100)
    creatorcomment = models.CharField(max_length=8092)
    uploadtime = models.DateTimeField("Created At", default=timezone.now)
    modtime = models.DateTimeField(auto_now=True)
    filehash = models.CharField(max_length=100, blank=True)

    def __str__(self) -> str:
        return f"{self.documentname}"


class Package(models.Model):
    """
    Model for holding data specific to SBOM packages uploaded.
    """

    id = models.AutoField(primary_key=True)
    sbomid_packages = models.ForeignKey(
        Sbom,
        on_delete=models.SET_NULL,
        null=True,
        related_name="packages_sbom",
        db_column="sbomid_packages",
    )
    packagename = models.CharField(max_length=100)
    packageversion = models.CharField(max_length=50)
    packagesupplier = models.CharField(max_length=50)
    packagecomment = models.CharField(max_length=8092)

    def __str__(self) -> str:
        return f"{self.packagename} | {self.sbomid_packages}"


class Cpe(models.Model):
    """
    Model for holding data specific to CPE's.
    """

    id = models.AutoField(primary_key=True)
    sbomid_cpe = models.ForeignKey(
        to=Sbom,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cpes_sbom",
        db_column="sbomid_cpe",
    )
    packageid_cpe = models.ForeignKey(
        Package,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cpes_package",
        db_column="packageid_cpe",
    )
    cpe = models.CharField(max_length=100)

    def __str__(self) -> str:
        return f"{self.cpe} | {self.sbomid_cpe} | {self.packageid_cpe}"


class Cve(models.Model):
    """
    Model for holding data specific to CVE's.
    """

    id = models.AutoField(primary_key=True)
    cpeid_cve = models.ForeignKey(
        Cpe,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cves_cpe",
        db_column="cpeid_cve",
    )
    packageid_cve = models.ForeignKey(
        Package,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cves_package",
        db_column="packageid_cve",
    )
    sbomid_cve = models.ForeignKey(
        Sbom,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cves_sbom",
        db_column="sbomid_cve",
    )
    cve = models.CharField(max_length=30)
    cve_sum = models.CharField(max_length=8092)
    cvss3_score = models.CharField(max_length=30)
    cvss3_severity = models.CharField(max_length=15)
    cvss3_vector = models.CharField(max_length=70)
    cve_exploit = models.CharField(max_length=8092, null=True)

    def __str__(self):
        return f"{self.cve} | {self.sbomid_cve} | {self.packageid_cve}"


class SbomUpload(models.Model):
    """
    Model for holding data specific to the status of the SBOM uploaded.
    """

    sbomfile = models.FileField(upload_to="sbom/", blank=True)
    filename = models.CharField(max_length=100, blank=True, default="")
    sbomid_sbomupload = models.ForeignKey(
        Sbom,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sbomupload",
        db_column="sbomid_sbomupload",
    )
    uploadtime = models.DateTimeField("Created At", default=timezone.now)
    sha1 = models.CharField(max_length=100, blank=True)
    job_id = models.CharField(max_length=100, blank=True)

    def save(self, *args, **kwargs):
        with self.sbomfile.open("rb") as f:
            hash = hashlib.sha1()
            if f.multiple_chunks():
                for chunk in f.chunks():
                    hash.update(chunk)
            else:
                hash.update(f.read())
            self.sha1 = hash.hexdigest()
            super(SbomUpload, self).save(*args, **kwargs)


class Ldap(models.Model):
    """
    Model for holding LDAP information.
    """

    server_uri = models.CharField(max_length=100, blank=True, default="")
    bind_dn = models.CharField(max_length=100, blank=True, default="")
    bind_password = models.CharField(
        max_length=300,
        blank=True,
        default="",
        help_text="Password is encrypted for security purposes.",
    )
    user_search = models.CharField(max_length=100, blank=True, default="")
    group_search = models.CharField(max_length=100, blank=True, default="")
    auth_ldap_group_type = models.CharField(max_length=100, blank=True, default="")
    auth_ldap_require_group = models.CharField(max_length=100, blank=True, default="")

    __original_pass = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__original_pass = self.bind_password

    def save(self, force_insert=False, force_update=False, *args, **kwargs):
        if self.bind_password != self.__original_pass:
            key = env("LDAP_BIND_PROTECTION")
            key_encoded = key.encode("utf-8")
            aes = pyaes.AESModeOfOperationCTR(key_encoded)
            self.bind_password = aes.encrypt(self.bind_password)
            super(Ldap, self).save(force_insert, force_update, *args, **kwargs)
            self.__original_pass = self.bind_password
        else:
            super(Ldap, self).save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.server_uri}"

    class Meta:
        verbose_name_plural = "LDAP"
        app_label = "auth"
