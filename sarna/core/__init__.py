from os import path

from flask import Flask

from sarna.config import DevelopmentConfig, ProductionConfig, BaseConfig
from werkzeug.contrib.fixers import ProxyFix

app = Flask(
    __name__,
    template_folder=path.join(BaseConfig.PROJECT_PATH, 'templates'),
    static_folder=path.join(BaseConfig.PROJECT_PATH, 'static')
)

if app.config['ENV'] == 'development':
    app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(ProductionConfig)

app.wsgi_app = ProxyFix(app.wsgi_app)

__all__ = [
    'app'
]
