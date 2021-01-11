from sarna.model.enums.base_choice import BaseChoice


class AuthSource(BaseChoice):
    _init_ = "value engine"
    database = 1, None
    ldap = 2, None
    ad = 3, None


class UserType(BaseChoice):
    auditor = 1
    trusted_auditor = 2
    manager = 3
    admin = 4


class UserAction(BaseChoice):
    init = 1
    create = 2
    login = 3
    update = 4
    delete = 5
