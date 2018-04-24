from flask import Blueprint, render_template
import os

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('index', __name__, template_folder='templates')


@blueprint.route('/')
def index():
    context = dict(
        route=ROUTE_NAME
    )
    return render_template('index.html', **context)
