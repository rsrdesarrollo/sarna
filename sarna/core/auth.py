from functools import wraps

from flask import abort
from flask_login import LoginManager, login_required, current_user, logout_user

from sarna.core import app
from sarna.model.enums.account import AccountType
from sarna.model.user import User

__all__ = [
    'login_manager', 'logout_user', 'login_required', 'current_user', 'admin_required', 'manager_required',
    'auditor_or_manager_required'
]

login_manager = LoginManager()

login_manager.login_view = "index.index"
login_manager.session_protection = "strong"
login_manager.login_message_category = 'success'

current_user: User = current_user


def admin_required(func):
    needs_accounts = {AccountType.admin}
    setattr(func, 'needs_accounts', {AccountType.admin})

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


def manager_required(func):
    needs_accounts = {AccountType.auditor, AccountType.manager}
    setattr(func, 'needs_accounts', {AccountType.manager})

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


def auditor_or_manager_required(func):
    needs_accounts = {AccountType.auditor, AccountType.manager}
    setattr(func, 'needs_accounts', needs_accounts)

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


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
