def is_ro(user):
    return user.groups.filter(name='Daggerboard_Read').exists()