from os import path

from flask import Flask

from sarna.config import DevelopmentConfig as ConfigClass
from werkzeug.contrib.fixers import ProxyFix

app = Flask(
    __name__,
    template_folder=path.join(ConfigClass.PROJECT_PATH, 'templates'),
    static_folder=path.join(ConfigClass.PROJECT_PATH, 'static')
)

app.config.from_object(ConfigClass)
app.wsgi_app = ProxyFix(app.wsgi_app)

__all__ = [
    'app'
]
