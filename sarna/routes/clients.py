import os
from uuid import uuid4

from flask import Blueprint, render_template, request, send_from_directory

from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, current_user
from sarna.forms import AssessmentForm, TemplateCreateNewForm
from sarna.forms import ClientForm
from sarna.model import Client, Assessment, Template
from sarna.model import db_session, select, commit, TransactionIntegrityError

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('clients', __name__)


@blueprint.route('/')
@db_session
@login_required
def index():
    context = dict(
        route=ROUTE_NAME,
        clients=select(client for client in Client)
    )
    return render_template('clients/list.html', **context)


@blueprint.route('/new', methods=('POST', 'GET'))
@db_session
@login_required
def new():
    form = ClientForm(request.form)
    context = dict(
        route=ROUTE_NAME,
        form=form
    )
    if form.validate_on_submit():
        Client(
            short_name=form.short_name.data,
            long_name=form.long_name.data,
            creator=current_user.username
        )
        return redirect_back('.index')

    return render_template('clients/new.html', **context)


@blueprint.route('/delete/<client_id>', methods=('POST',))
@db_session
@login_required
def delete(client_id: int):
    Client[client_id].delete()
    return redirect_back('.index')


@blueprint.route('/<client_id>', methods=('POST', 'GET'))
@db_session
@login_required
def edit(client_id: int):
    client = Client[client_id]

    form_data = request.form.to_dict() or client.to_dict()
    form = ClientForm(**form_data)
    context = dict(
        route=ROUTE_NAME,
        form=form,
        client=client
    )
    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        client.set(**data)
        return redirect_back('.index')
    return render_template('clients/details.html', **context)


@blueprint.route('/<client_id>/add_assessment', methods=('POST', 'GET'))
@db_session
@login_required
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

        Assessment(client=client, creator=current_user.username, **data)
        return redirect_back('.edit', client_id=client_id)
    return render_template('clients/add_assessment.html', **context)


@blueprint.route('/<client_id>/add_template', methods=('POST', 'GET'))
@db_session
@login_required
def add_template(client_id: int):
    client = Client[client_id]
    form = TemplateCreateNewForm()
    context = dict(
        route=ROUTE_NAME,
        form=form,
        client=client
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)

        file = data.pop('file')
        filename = "{}.{}".format(uuid4(), file.filename.split('.')[-1])

        data['file'] = filename

        upload_path = client.template_path()
        if not os.path.exists(upload_path):
            os.makedirs(upload_path)

        try:
            Template(client=client, **data)
            commit()
            file.save(os.path.join(upload_path, filename))
            return redirect_back('.edit', client_id=client_id)
        except TransactionIntegrityError:
            form.name.errors.append('Name already used')

    return render_template('clients/add_template.html', **context)


@blueprint.route('/<client_id>/template/<template_name>/delete', methods=('POST',))
@db_session
@login_required
def delete_template(client_id: int, template_name):
    client = Client[client_id]
    template = Template[client, template_name]
    os.remove(os.path.join(client.template_path(), template.file))
    template.delete()
    return redirect_back('.edit', client_id=client_id)


@blueprint.route('/<client_id>/template/<template_name>/download')
@db_session
@login_required
def download_template(client_id: int, template_name):
    client = Client[client_id]
    template = Template[client, template_name]
    return send_from_directory(
        client.template_path(),
        template.file,
        as_attachment=True,
        attachment_filename="{}.{}".format(template.name, template.file.split('.')[-1])
    )
