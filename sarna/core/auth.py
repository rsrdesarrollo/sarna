from functools import wraps

from flask_login import LoginManager, login_required, current_user, logout_user

from sarna.model.enums.account import AccountType
from sarna.model.user import User

__all__ = ['login_manager', 'logout_user', 'login_required', 'current_user', 'admin_required']

login_manager = LoginManager()

login_manager.login_view = "index.index"
login_manager.session_protection = "strong"
login_manager.login_message_category = 'success'

current_user: User = current_user


def admin_required(func):
    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.user_type == AccountType.admin:
            return login_manager.unauthorized()
        else:
            return func(*args, **kwargs)

    return decorated_view


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()
