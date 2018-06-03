from os import path

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2 per second"]
)

PROJECT_PATH = path.realpath(
    path.join(
        path.dirname(__file__),
        *(['..']*len(__name__.split('.')))
    )
)

TEMPLATE_DIR = path.join(PROJECT_PATH, 'templates')
STATIC_DIR = path.join(PROJECT_PATH, 'static')

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)

__all__ = ['app', 'csrf', 'limiter', 'PROJECT_PATH', 'TEMPLATE_DIR', 'STATIC_DIR']
