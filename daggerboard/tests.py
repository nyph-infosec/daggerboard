# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

from daggerboard.tasks import search_log_file
from unittest.mock import patch, mock_open
import unittest
import secrets

"""

    1. In the terminal, navigate to where manage.py is located.
    2. Run python manage.py test daggerboard.tests

"""

class TestSearchLogFile(unittest.TestCase):
    """
    Test the search_log_file function in daggerboard/tasks.py
    
    The search_log_file function is used to check the status of a
    background job that processes an uploaded SBOM file. The function
    searches the log file for a line that contains the SBOM hash and

    1. returns a dictionary with the key "sbomprocess_complete" set to
         True and the key "result" set to 1 if the SBOM file has been
         processed successfully,
    2. returns a dictionary with the key "sbomprocess_complete" set to
            True and the key "result" set to 2 if the SBOM file has already
            been processed,
    3. returns a dictionary with the key "sbomprocess_complete" set to
            False and the key "result" set to 0 if the SBOM file has not
            yet been processed.
    """
    @patch("builtins.open", new_callable=mock_open)
    def test_search_log_file(self, mock_open):
        sbom_hash = secrets.token_hex(16)
        mock_file = mock_open.return_value
        mock_file.readlines.return_value = [
            f"INFO-1-{sbom_hash}\n",
            f"ERR-2-{sbom_hash}\n",
            f"INFO-00-{sbom_hash}\n",
        ]
        result = search_log_file(sbom_hash)
        # check that the function returns a dictionary
        self.assertIsInstance(result, dict)
        # check that the function returns the correct dictionary
        self.assertEqual(result, {
            "sbomprocess_complete": True,
            "result": 2,
            "err": "File has already been processed.",
        })

    
# class UnitTestCases(TestCase):
#     def setUp(self):
#         self.client = Client()

#     def test_login_and_dashboard_page(self):
#         self.user = User.objects.create(username="testuser")
#         self.user.set_password("12345")
#         self.user.save()
#         response_login = self.client.post(
#             reverse("home"), {"user_id": self.user.id}, follow=True
#         )
#         self.assertEqual(response_login.status_code, 200)

#     def test_sbom_page(self):
#         response_sbom = self.client.get("/sbomscorecard", follow=True)
#         self.assertEqual(response_sbom.status_code, 200)

#     def test_vendor_page(self):
#         response_vendor = self.client.get("/vendorscorecard", follow=True)
#         self.assertEqual(response_vendor.status_code, 200)

#     def test_admin_page(self):
#         response_admin = self.client.get("/admin", follow=True)
#         self.assertEqual(response_admin.status_code, 200)

