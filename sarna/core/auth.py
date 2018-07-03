from flask_login import LoginManager, login_required, current_user, logout_user

from sarna.core import app
from sarna.model.user import User

__all__ = [
    'login_manager', 'logout_user', 'login_required', 'current_user'
]

login_manager = LoginManager()

login_manager.login_view = "index.index"
login_manager.session_protection = "strong"
login_manager.login_message_category = 'success'

current_user: User = current_user


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()


@app.context_processor
def processor_can_view():
    def can_view(endpoint: str):
        if current_user.is_anonymous:
            return False

        view_func = app.view_functions.get(endpoint, None)
        if view_func:
            needs = getattr(view_func, 'needs_accounts', None)
            if needs:
                return current_user.user_type in needs
        return True

    return dict(can_view=can_view)
