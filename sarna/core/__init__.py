from os import path

from flask import Flask

from sarna.config import DevelopmentConfig as ConfigClass

app = Flask(
    __name__,
    template_folder=path.join(ConfigClass.PROJECT_PATH, 'templates'),
    static_folder=path.join(ConfigClass.PROJECT_PATH, 'static')
)

app.config.from_object(ConfigClass)

__all__ = [
    'app'
]
