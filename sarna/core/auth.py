from functools import wraps

from flask_login import LoginManager, login_required, current_user, logout_user

from sarna.model import User

__all__ = ['login_manager', 'logout_user', 'login_required', 'current_user', 'admin_required']

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
    return User.query.filter_by(username=user_id).first()
