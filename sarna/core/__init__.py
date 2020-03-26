import itertools
from os import path

from flask import Flask, request
from werkzeug.contrib.fixers import ProxyFix

from sarna.config import DevelopmentConfig, ProductionConfig, BaseConfig

APP_VERSION = "v1.0.6"

app = Flask(
    __name__,
    template_folder=path.join(BaseConfig.PROJECT_PATH, 'templates'),
    static_folder=path.join(BaseConfig.PROJECT_PATH, 'static')
)

if app.config['ENV'] == 'development':
    app.config.from_object(DevelopmentConfig)
    try:
        from flask_debugtoolbar import DebugToolbarExtension

        toolbar = DebugToolbarExtension(app)
    except ImportError:
        pass
else:
    app.config.from_object(ProductionConfig)

app.wsgi_app = ProxyFix(app.wsgi_app)


@app.context_processor
def processor_endpoint():
    def is_endpoint(endpoint: str):
        if not request.endpoint:
            return False

        for a, b in itertools.zip_longest(request.endpoint.split('.'), endpoint.split('.')):
            if not a or (b and b != a):
                return False
        return True

    return dict(is_endpoint=is_endpoint)


@app.context_processor
def inyect_app_version():
    return dict(app_version=APP_VERSION)

__all__ = [
    'app'
]
