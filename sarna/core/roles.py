from functools import wraps

from flask_login import login_required
from werkzeug.exceptions import abort

from sarna.model.enums import UserType

valid_auditors = {UserType.manager, UserType.trusted_auditor, UserType.auditor}
valid_trusted = {UserType.manager, UserType.trusted_auditor}
valid_managers = {UserType.manager}
valid_admins = {UserType.admin}

def role_handler(func, roles):
    from sarna.core.auth import current_user
    
    needs_accounts = roles | valid_admins
    setattr(func, 'needs_accounts', needs_accounts)

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


def admin_required(func):
    return role_handler(func, valid_admins)
    

def manager_required(func):
    return role_handler(func, valid_managers)


def trusted_required(func):
    return role_handler(func, valid_trusted)


def auditor_required(func):
    return role_handler(func, valid_auditors)
