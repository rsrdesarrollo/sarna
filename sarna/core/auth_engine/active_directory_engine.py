import ssl

import ldap3
from ldap3.core.exceptions import LDAPCommunicationError, LDAPConfigurationError
from ldap3.utils.conv import escape_filter_chars

from sarna.core.auth_engine.base_engine import BaseEngine
from sarna.core.auth_engine.exceptions import *
from sarna.core.config import config
from sarna.model import User
from sarna.model.enums import UserType, AuthSource


class ActiveDirectoryEngine(BaseEngine):

    @staticmethod
    def auth_source():
        return AuthSource.ad

    @staticmethod
    def get_user(username):
        username = escape_filter_chars(username).lower()

        user = User.query.filter_by(username=username).first()

        if not user and not config.AD_FALLBACK:
            raise UserNotFoundException()
        elif not user:
            user = User(
                username=username,
                source=ActiveDirectoryEngine.auth_source(),
                is_locked=False,
                login_try=0,
                otp_enabled=False
            )

        return user

    @staticmethod
    def verify_passwd(user: User, password):
        try:
            tls_config = ldap3.Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLSv1_2,
                ca_certs_file=config.AD_CA_CERT_PATH
            )
            server = ldap3.Server(config.AD_SERVER_URI, tls=tls_config)
        except LDAPConfigurationError as ex:
            raise AuthEngineFailedException('ERROR in AD Configuration. {}'.format(ex))

        with ldap3.Connection(server) as conn:
            try:
                conn.bind()
                if not server.ssl:
                    conn.start_tls()
            except LDAPCommunicationError as ex:
                raise AuthEngineFailedException(
                    'ERROR: connecting to AD Backend. {}'.format(ex)
                )

            bind_ok = conn.rebind(
                '{domain}\\{username}'.format(
                    domain=config.AD_DOMAIN,
                    username=user.username
                ),
                password,
                authentication=ldap3.NTLM
            )

            if not bind_ok:
                raise InvalidCredentialsException()

            if config.AD_BIND_USER:
                bind_ok = conn.rebind(
                    '{domain}\\{username}'.format(
                        domain=config.AD_DOMAIN,
                        username=config.AD_BIND_USER
                    ),
                    config.AD_BIND_PASSWORD,
                    authentication=ldap3.NTLM
                )

            if not bind_ok:
                raise AuthEngineFailedException('Invalid bind user')

            conn.search(
                config.AD_BASE_DN,
                config.AD_USER_FILTER.format(username=user.username),
                attributes=[config.AD_GROUP_ATTR]
            )

            try:
                entry = conn.entries[0]
            except IndexError:
                raise AuthEngineFailedException('Unable to find user entry in AD')

            user_type = ActiveDirectoryEngine.get_entry_user_type(entry)

            if config.AD_AUTO_ROLE_MAPPING:
                # If auto mapping, force user role.
                user.user_type = user_type

    @staticmethod
    def get_entry_user_type(entry):
        groups = getattr(entry, config.AD_GROUP_ATTR, None)

        if not groups and config.AD_GROUP_REQUIRED:
            raise UnauthorizedAccountException(
                'No groups on user referenced by attribute {}'.format(config.AD_GROUP_ATTR)
            )

        groups = set(groups.value)

        if config.AD_GROUP_REQUIRED and config.AD_GROUP_REQUIRED not in groups:
            raise UnauthorizedAccountException(
                'User does not have required group {}'.format(config.AD_GROUP_REQUIRED)
            )

        user_type = UserType.auditor

        if config.AD_AUTO_ROLE_MAPPING:
            if config.AD_ADMIN_GROUP and config.AD_ADMIN_GROUP in groups:
                user_type = UserType.admin
            elif config.AD_MANAGER_GROUP and config.AD_MANAGER_GROUP in groups:
                user_type = UserType.manager
            elif config.AD_TRUSTED_AUDITOR_GROUP and config.AD_TRUSTED_AUDITOR_GROUP in groups:
                user_type = UserType.trusted_auditor
            elif config.AD_AUDITOR_GROUP and config.AD_AUDITOR_GROUP in groups:
                user_type = UserType.auditor
            else:
                raise UnauthorizedAccountException('No mapping found for user')

        return user_type

    @staticmethod
    def change_password(user: User, password, new_password, otp=None):
        raise AuthEngineFailedException('not implemented')
