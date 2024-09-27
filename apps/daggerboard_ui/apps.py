# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

from django.apps import AppConfig


class DaggerboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.daggerboard_ui"
