# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

from django import template

register = template.Library()

@register.filter(name='has_group')
def has_group(user, group_name):
    return user.groups.filter(name=group_name).exists()

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter
def gradeThresholdAdminSplit(string, split_at):
    '''
    Custom template tag for custom grade threshold admin panel
    '''
    if "And less " not in string:
        splitString = string.split(split_at)
        letterGrade = splitString[0].split(">")[1].strip()
        lessGreatThan = splitString[1].split(":")[0].strip()
        arr = [letterGrade, lessGreatThan]
        return arr
    else:
        return string