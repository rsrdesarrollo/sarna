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


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ASSETS_DEBUG = True
    SECRET_KEY = "SECRET RANDOM STR CHANGE ME"
    TEMPLATES_AUTO_RELOAD = True


class ProductionConfig(DevelopmentConfig):
    DEBUG = False
    ASSETS_DEBUG = False
    SECRET_KEY = ''
    TEMPLATES_AUTO_RELOAD = False


_conf_file = path.join(BaseConfig.PROJECT_PATH, 'config', 'config.yaml')
if path.isfile(_conf_file):
    import yaml

    with open(_conf_file, 'r') as fh:
        data = yaml.safe_load(fh)

    for k, v in data.items():
        setattr(ProductionConfig, k, v)
        setattr(DevelopmentConfig, k, v)
