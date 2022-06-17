# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

from django.contrib import admin
from .models import Sbom, Cpe, Cve, Package, Ldap

@admin.register(Sbom)
class SBOMAdmin(admin.ModelAdmin):
    list_display = ['documentname','vendorname','uploadtime']
    list_filter = ('uploadtime','documentname','vendorname')
    search_fields = ['documentname','vendorname']

@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    list_display = ['packagename','packageversion','sbomid_packages']
    list_filter = ['packagename']
    search_fields = ['packagename']

@admin.register(Cpe)
class CPEAdmin(admin.ModelAdmin):
    list_display = ['cpe', 'sbomid_cpe', 'packageid_cpe']
    list_filter = ['sbomid_cpe']
    search_fields = ['cpe']

@admin.register(Cve)
class CVEAdmin(admin.ModelAdmin):
    list_display = ['cve','sbomid_cve','packageid_cve']
    list_filter = ['cve','cvss3_severity']
    search_fields = ['cve']

@admin.register(Ldap)
class LDAPAdmin(admin.ModelAdmin):
    list_display = [
            'server_uri',
            'bind_dn',
            'bind_password',
            'user_search',
            'group_search',
            'auth_ldap_group_type',
            'auth_ldap_require_group'
        ]

    # restrict to one LDAP entry
    def has_add_permission(self, request):
        return False if self.model.objects.count() > 0 else super().has_add_permission(request)

