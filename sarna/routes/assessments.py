from flask import Blueprint, render_template, redirect, url_for, request
from sarna.model import Assessment
from sarna.model import db_session, select
from sarna.forms import AssessmentForm

import os

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('assessments', __name__)


@blueprint.route('/')
@db_session()
def index():
    pass

@blueprint.route('/<assessment_id>')
@db_session()
def details():
    pass

@blueprint.route('/<assessment_id>/delete')
@db_session()
def delete():
    pass

@blueprint.route('/new')
@db_session()
def new():
    pass