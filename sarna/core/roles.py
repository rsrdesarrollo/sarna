from functools import wraps

from flask_login import login_required
from werkzeug.exceptions import abort

from sarna.model import Finding, Assessment
from sarna.model.enums import UserType

valid_trusted = {UserType.trusted_auditor, UserType.auditor, UserType.manager, UserType.admin}
valid_auditors = {UserType.auditor, UserType.manager, UserType.admin}
valid_managers = {UserType.manager, UserType.admin}
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


def assessment_allowed(func):
    from sarna.core.auth import current_user

    @wraps(func)
    @login_required
    def decorated_view(*args, **kwargs):
        assessment: Assessment
        finding: Finding

        if kwargs.get('assessment_id'):
            assessment = Assessment.query.filter_by(id=kwargs.get('assessment_id')).one()
            kwargs['assessment'] = assessment
        else:
            abort(400, description='Missing assessment ID')

        if not current_user.is_readonly and \
                not current_user.is_admin and \
                not current_user.manages(assessment) and \
                not current_user.audits(assessment):
            abort(403)

        if kwargs.get('finding_id'):
            finding = Finding.query.filter_by(id=kwargs.get('finding_id')).one()
            if assessment.id != finding.assessment.id:
                abort(404,
                      description='No finding found with {} ID for this assessment.'.format(finding.id))
            kwargs['finding'] = finding

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
