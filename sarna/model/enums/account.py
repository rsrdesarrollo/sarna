from sarna.model.enums.base_choice import BaseChoice


class AuthSource(BaseChoice):
    database = 1
    ldap = 2


class AccountType(BaseChoice):
    auditor = 1
    manager = 2
    admin = 3
