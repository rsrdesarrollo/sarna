import os
from os import path
from secrets import token_urlsafe


class DevelopmentConfig:
    DEBUG = True
    WTF_CSRF_SECRET_KEY = "SECRET RANDOM STR CHANGE ME"
    SECRET_KEY = "SECRET RANDOM STR CHANGE ME"
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 Mb limit
    ASSETS_DEBUG = True
    PROJECT_PATH = path.realpath(
        path.join(
            __file__,
            *(['..'] * len(__name__.split('.')))
        )
    )

    _default_database_path = path.join(PROJECT_PATH, 'database')
    _default_evidences_path = path.join(PROJECT_PATH, 'uploaded_data', 'evidences')
    _default_templates_path = path.join(PROJECT_PATH, 'uploaded_data', 'templates')

    DATABASE_PATH = path.abspath(os.getenv('SARNA_DATABASE_PATH', _default_database_path))

    EVIDENCES_PATH = path.abspath(os.getenv('SARNA_EVIDENCES_PATH', _default_evidences_path))
    EVIDENCES_ALLOW_EXTENSIONS = {'png', 'jpeg', 'jpg', 'bmp'}
    EVIDENCES_ALLOW_MIME = 'image/.*'

    TEMPLATES_PATH = path.abspath(os.getenv('SARNA_TEMPLATES_PATH', _default_templates_path))
    TEMPLATES_ALLOW_EXTENSIONS = {'docx'}
    TEMPLATES_ALLOW_MIME = 'application/.*'


class ProductionConfig(DevelopmentConfig):
    DEBUG = False
    ASSETS_DEBUG = False
    WTF_CSRF_SECRET_KEY = token_urlsafe(64)
    SECRET_KEY = token_urlsafe(64)
