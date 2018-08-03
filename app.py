from flask import render_template, request
from sqlalchemy.orm.exc import NoResultFound
from werkzeug import exceptions

from sarna.commands import user_cli
from sarna.core import app
from sarna.core import asset
from sarna.core.auth import login_manager
from sarna.core.auth_engine import auth_controller
from sarna.core.security import csrf, limiter
from sarna.routes import clients, index, findings, users, assessments


def error_handler(err):
    if request.is_xhr:
        return str(err), err.code

    if isinstance(err, ValueError):
        err = exceptions.BadRequest()
    elif isinstance(err, NoResultFound):
        err = exceptions.NotFound()

    try:
        context = dict(
            code=err.code,
            error=err.name,
            description=err.description,
        )
    except AttributeError:
        context = dict(
            code=500,
            error='Internal Server Error',
            description=str(err),
        )

    return render_template('error.html', **context), context['code']


csrf.init_app(app)
limiter.init_app(app)
asset.init_app(app)

login_manager.init_app(app)
auth_controller.init_app(app)

user_cli.init_app(app)

app.register_blueprint(index.blueprint)
app.register_blueprint(clients.blueprint, url_prefix='/clients')
app.register_blueprint(assessments.blueprint, url_prefix='/assessments')
app.register_blueprint(findings.blueprint, url_prefix='/findings')
app.register_blueprint(users.blueprint, url_prefix='/users')

app.register_error_handler(400, error_handler)
app.register_error_handler(401, error_handler)
app.register_error_handler(403, error_handler)
app.register_error_handler(404, error_handler)
app.register_error_handler(405, error_handler)
app.register_error_handler(408, error_handler)
app.register_error_handler(409, error_handler)
app.register_error_handler(413, error_handler)
app.register_error_handler(429, error_handler)
app.register_error_handler(500, error_handler)
app.register_error_handler(501, error_handler)
app.register_error_handler(502, error_handler)
app.register_error_handler(503, error_handler)
app.register_error_handler(504, error_handler)
