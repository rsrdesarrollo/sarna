import os
from flask import Flask, render_template, request
from sarna.model import init_database
from sarna.routes import clients, index, findings, users, assessments
from secrets import token_urlsafe
from sarna import csrf

init_database()

BASE_DIR = os.path.dirname(__file__)
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__)


def error_handler(err):
    if request.headers.get('x-requested-with', '') == "XMLHttpRequest":
        return str(err), err.code

    return render_template('error.html', error=str(err)), err.code


app.register_blueprint(index.blueprint)
app.register_blueprint(clients.blueprint, url_prefix='/clients')
app.register_blueprint(assessments.blueprint, url_prefix='/assessments')
app.register_blueprint(findings.blueprint, url_prefix='/findings')
app.register_blueprint(users.blueprint, url_prefix='/users')

app.register_error_handler(400, error_handler)
app.register_error_handler(404, error_handler)
app.register_error_handler(500, error_handler)

if __name__ == '__main__':
    csrf.init_app(app)
    app.config.update(
        DEBUG=True,
        WTF_CSRF_SECRET_KEY=token_urlsafe(64),
        SECRET_KEY=token_urlsafe(64)
    )

    extra_files = ["templates"]
    for dirname, dirs, files in os.walk("templates"):
        for file in files:
            extra_files.append(os.path.join(dirname, file))

    app.run(
        extra_files=extra_files
    )
