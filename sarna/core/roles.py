from functools import wraps

from flask_login import login_required
from werkzeug.exceptions import abort

from sarna.model.enums import UserType

valid_auditors = {UserType.manager, UserType.trusted_auditor, UserType.auditor}
valid_trusted = {UserType.manager, UserType.trusted_auditor}
valid_managers = {UserType.manager}
valid_admins = {UserType.admin}


def admin_required(func):
    from sarna.core.auth import current_user

    needs_accounts = valid_admins
    setattr(func, 'needs_accounts', needs_accounts)

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


def manager_required(func):
    from sarna.core.auth import current_user
    needs_accounts = valid_managers
    setattr(func, 'needs_accounts', needs_accounts)

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


def trusted_required(func):
    from sarna.core.auth import current_user

    needs_accounts = valid_trusted
    setattr(func, 'needs_accounts', needs_accounts)

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view


def auditor_required(func):
    from sarna.core.auth import current_user

    needs_accounts = valid_auditors
    setattr(func, 'needs_accounts', needs_accounts)

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        if current_user.user_type not in needs_accounts:
            abort(403)
        else:
            return func(*args, **kwargs)

    return decorated_view
