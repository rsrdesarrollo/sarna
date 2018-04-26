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
    context = dict(
        route=ROUTE_NAME,
        assessments=select(assessment for assessment in Assessment)[:]
    )
    return render_template('assessments/list.html', **context)

@blueprint.route('/<assessment_id>')
@db_session()
def edit(assessment_id):
    pass

@blueprint.route('/<assessment_id>/delete')
@db_session()
def delete(assessment_id):
    pass

@blueprint.route('/new')
@db_session()
def new():
    pass