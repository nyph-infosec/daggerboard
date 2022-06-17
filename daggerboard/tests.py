# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse


class UnitTestCases(TestCase):
    def setUp(self):
        self.client = Client()

    def test_login_and_dashboard_page(self):
        self.user = User.objects.create(username="testuser")
        self.user.set_password("12345")
        self.user.save()
        response_login = self.client.post(
            reverse("home"), {"user_id": self.user.id}, follow=True
        )
        self.assertEqual(response_login.status_code, 200)

    def test_sbom_page(self):
        response_sbom = self.client.get("/sbomscorecard", follow=True)
        self.assertEqual(response_sbom.status_code, 200)

    def test_vendor_page(self):
        response_vendor = self.client.get("/vendorscorecard", follow=True)
        self.assertEqual(response_vendor.status_code, 200)

    def test_admin_page(self):
        response_admin = self.client.get("/admin", follow=True)
        self.assertEqual(response_admin.status_code, 200)