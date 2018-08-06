from typing import List

from wtforms import ValidationError

from sarna.core.roles import valid_auditors, valid_managers
from sarna.model import User


def users_are_managers(_, field):
    users: List[User] = field.data

    if type(users) != list:
        users = [users]

    for user in users:
        if user.user_type not in valid_managers:
            raise ValidationError('user {} is not a manager'.format(user.name))


def user_is_auditor(_, field):
    users: List[User] = field.data

    if type(users) != list:
        users = list(users)

    for user in users:
        if user.user_type not in valid_auditors:
            raise ValidationError('user {} is not an auditor'.format(user.name))
