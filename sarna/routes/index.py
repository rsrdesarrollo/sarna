import os

from flask import Blueprint, render_template

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('index', __name__)


@blueprint.route('/')
def index():
    context = dict(
        route=ROUTE_NAME
    )
    return render_template('index.html', **context)


@blueprint.route('/login', methods=('GET', 'POST'))
def login():
    pass

@blueprint.route('/logout')
def logout():
    pass