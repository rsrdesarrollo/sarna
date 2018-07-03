from sarna.model.enums.base_choice import BaseChoice


class AuthSource(BaseChoice):
    database = 1
    ldap = 2


class AccountType(BaseChoice):
    auditor = 1
    trusted_auditor = 2
    manager = 3
    admin = 4
