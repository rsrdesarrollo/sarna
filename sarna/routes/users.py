import os

from flask import Blueprint

from sarna.model import db_session

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('users', __name__)


@blueprint.route('/')
@db_session()
def index():
    pass
