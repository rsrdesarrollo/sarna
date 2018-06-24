from os import path

from flask import Flask

from sarna.config import DevelopmentConfig, ProductionConfig, BaseConfig

app = Flask(
    __name__,
    template_folder=path.join(BaseConfig.PROJECT_PATH, 'templates'),
    static_folder=path.join(BaseConfig.PROJECT_PATH, 'static')
)

if app.config['ENV'] == 'development':
    app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(ProductionConfig)

__all__ = [
    'app'
]
