import os
from os import path


class BaseConfig:
    PROJECT_PATH = path.realpath(
        path.join(
            __file__,
            *(['..'] * len(__name__.split('.')))
        )
    )

    _default_database_uri = 'postgres://user:password@localhost/sarna'
    _default_ldap_uri = 'ldap://localhost'

    _default_evidences_path = path.join(PROJECT_PATH, 'uploaded_data', 'evidences')
    _default_templates_path = path.join(PROJECT_PATH, 'uploaded_data', 'templates')
    _default_ldap_ca_path = path.join(PROJECT_PATH, 'config', 'cacert.cer')

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 Mb limit

    EVIDENCES_PATH = path.abspath(os.getenv('SARNA_EVIDENCES_PATH', _default_evidences_path))
    EVIDENCES_ALLOW_EXTENSIONS = {'png', 'jpeg', 'jpg', 'bmp'}
    EVIDENCES_ALLOW_MIME = 'image/.*'

    TEMPLATES_PATH = path.abspath(os.getenv('SARNA_TEMPLATES_PATH', _default_templates_path))
    TEMPLATES_ALLOW_EXTENSIONS = {'docx'}
    TEMPLATES_ALLOW_MIME = 'application/.*'

    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', _default_database_uri)

    SECRET_KEY = os.getenv('SECRET_KEY', "")

    AD_FALLBACK = False
    AD_AUTO_ROLE_MAPPING = False
    AD_GROUP_REQUIRED = ''
    AD_DOMAIN = ''
    AD_SERVER_URI = _default_ldap_uri
    AD_CA_CERT_PATH = _default_ldap_ca_path
    AD_BASE_DN = ''
    AD_BIND_USER = ''
    AD_BIND_PASSWORD = ''

    AD_AUDITOR_GROUP = ''
    AD_TRUSTED_AUDITOR_GROUP = ''
    AD_MANAGER_GROUP = ''
    AD_ADMIN_GROUP = ''

    AD_USER_FILTER = '(&(objectClass=person)(sAMAccountName={username}))'
    AD_GROUP_ATTR = 'memberOf'

    # Enable Federated authentication, you must complete the attributes below
    SAML_AUTH = os.getenv('SAML_AUTH')
    # Identity Provider URL
    SAML_IDP_EID = os.getenv('SAML_IDP_EID')
    # Identity provider's SSO Url
    SAML_IDP_SSO = os.getenv('SAML_IDP_SSO')
    # Identity provider's SLO Url
    SAML_IDP_SLO = os.getenv('SAML_IDP_SLO')
    # IDP's certificate path
    SAML_IDP_CERT = os.getenv('SAML_IDP_CERT')
    # SP's certificate path
    SAML_SP_CERT = os.getenv('SAML_SP_CERT')
    # SP's private key path
    SAML_SP_PK = os.getenv('SAML_SP_PK')
    # SP server name
    SERVER_NAME = os.getenv('SERVER_NAME')

    # User session timeout in seconds.
    PERMANENT_SESSION_LIFETIME = 604800
    # Refresh the session cookie with every request, extending the timeout.
    SESSION_REFRESH_EACH_REQUEST = False
    # User session protection based on a hash of the IP address and user agent.
    SESSION_PROTECTION = None


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ASSETS_DEBUG = True
    TEMPLATES_AUTO_RELOAD = True


class ProductionConfig(DevelopmentConfig):
    DEBUG = False
    ASSETS_DEBUG = False
    TEMPLATES_AUTO_RELOAD = False


_conf_file = path.join(BaseConfig.PROJECT_PATH, 'config', 'config.yaml')
if path.isfile(_conf_file):
    import yaml

    with open(_conf_file, 'r') as fh:
        data = yaml.safe_load(fh)

    for k, v in data.items():
        setattr(ProductionConfig, k, v)
        setattr(DevelopmentConfig, k, v)
