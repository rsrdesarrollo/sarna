from flask import Blueprint, render_template, redirect, url_for, request
from sarna.model import Client, Assessment
from sarna.model import db_session, select
from sarna.forms import ClientForm
from sarna.forms import AssessmentForm

import os

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('clients', __name__)


@blueprint.route('/')
@db_session()
def index():
    context = dict(
        route=ROUTE_NAME,
        clients=select(client for client in Client)[:]
    )
    return render_template('clients/list.html', **context)


@blueprint.route('/new', methods=('POST', 'GET'))
@db_session()
def new():
    form = ClientForm(request.form)
    context = dict(
        route=ROUTE_NAME,
        form=form
    )
    if form.validate_on_submit():
        Client(
            short_name=form.short_name.data,
            long_name=form.long_name.data
        )
        return redirect(url_for('.index'))

    return render_template('clients/new.html', **context)


@blueprint.route('/delete/<client_id>')
@db_session()
def delete(client_id: int):
    Client[client_id].delete()
    return redirect(url_for('.index'))


@blueprint.route('/<client_id>', methods=('POST', 'GET'))
@db_session()
def details_client(client_id: int):
    client = Client[client_id]
    form = ClientForm(**client.to_dict())
    context = dict(
        route=ROUTE_NAME,
        form=form,
        client=client
    )
    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        Client[client_id].set(**data)
        return redirect(url_for('.index'))
    return render_template('clients/details.html', **context)


@blueprint.route('/<client_id>/add_assessment', methods=('POST', 'GET'))
@db_session()
def add_assessment(client_id: int):
    client = Client[client_id]
    form = AssessmentForm(request.form)
    context = dict(
        route=ROUTE_NAME,
        form=form,
        client=client
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        data.pop('client_id', None)

        Assessment(client=client, **data)
        return redirect(url_for('.details_client', client_id=client_id))
    return render_template('clients/add_assessment.html', **context)
