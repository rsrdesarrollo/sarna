import os
from os import path
from secrets import token_urlsafe


class BaseConfig:
    PROJECT_PATH = path.realpath(
        path.join(
            __file__,
            *(['..'] * len(__name__.split('.')))
        )
    )

    _default_database_uri = 'postgres://user:password@localhost/sarna'
    _default_evidences_path = path.join(PROJECT_PATH, 'uploaded_data', 'evidences')
    _default_templates_path = path.join(PROJECT_PATH, 'uploaded_data', 'templates')

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 Mb limit

    EVIDENCES_PATH = path.abspath(os.getenv('SARNA_EVIDENCES_PATH', _default_evidences_path))
    EVIDENCES_ALLOW_EXTENSIONS = {'png', 'jpeg', 'jpg', 'bmp'}
    EVIDENCES_ALLOW_MIME = 'image/.*'

    TEMPLATES_PATH = path.abspath(os.getenv('SARNA_TEMPLATES_PATH', _default_templates_path))
    TEMPLATES_ALLOW_EXTENSIONS = {'docx'}
    TEMPLATES_ALLOW_MIME = 'application/.*'

    SQLALCHEMY_DATABASE_URI = os.getenv('SARNA_DATABASE_URI', _default_database_uri)


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ASSETS_DEBUG = True
    WTF_CSRF_SECRET_KEY = "SECRET RANDOM STR CHANGE ME"
    SECRET_KEY = "SECRET RANDOM STR CHANGE ME"
    TEMPLATES_AUTO_RELOAD = True


class ProductionConfig(DevelopmentConfig):
    DEBUG = False
    ASSETS_DEBUG = False
    WTF_CSRF_SECRET_KEY = token_urlsafe(64)
    SECRET_KEY = token_urlsafe(64)
    TEMPLATES_AUTO_RELOAD = False


_conf_file = path.join(BaseConfig.PROJECT_PATH, 'config', 'config.yaml')
if path.isfile(_conf_file):
    import yaml

    with open(_conf_file, 'r') as fh:
        data = yaml.safe_load(fh)

    for k, v in data.items():
        setattr(ProductionConfig, k, v)
        setattr(DevelopmentConfig, k, v)
