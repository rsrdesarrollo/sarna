from functools import wraps
from os import path

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_required, current_user, logout_user
from flask_wtf.csrf import CSRFProtect

from sarna.config import DevelopmentConfig as ConfigClass

login_manager = LoginManager()
login_manager.login_view = "index.index"
login_manager.session_protection = "strong"
login_manager.login_message_category = 'success'


def admin_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            return login_manager.unauthorized()
        else:
            return func(*args, **kwargs)

    return decorated_view


@login_manager.user_loader
def load_user(user_id):
    from sarna.model import User
    return User[user_id]


csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2 per second"]
)

app = Flask(
    __name__,
    template_folder=path.join(ConfigClass.PROJECT_PATH, 'templates'),
    static_folder=path.join(ConfigClass.PROJECT_PATH, 'static')
)

app.config.from_object(ConfigClass)

__all__ = [
    'app', 'csrf', 'limiter', 'login_required', 'current_user', 'logout_user', 'login_manager'
]
