# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT


def is_ro(user):
    return user.groups.filter(name="Daggerboard_Read").exists()
