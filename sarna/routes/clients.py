import os
from uuid import uuid4

from flask import Blueprint, render_template, request, send_from_directory, abort
from sqlalchemy.exc import IntegrityError

from sarna.auxiliary import redirect_back
from sarna.core.auth import current_user
from sarna.core.roles import valid_auditors, valid_managers, manager_required
from sarna.forms.assessment import AssessmentForm
from sarna.forms.client import ClientForm, TemplateCreateNewForm, ClientChangeOwnerForm
from sarna.model import Assessment, db
from sarna.model.client import Client, Template
from sarna.model.user import User

blueprint = Blueprint('clients', __name__)


@blueprint.route('/')
@manager_required
def index():
    clients = Client.query.filter(
        (Client.creator == current_user) |
        (Client.managers.any(User.id == current_user.id)) |
        (Client.auditors.any(User.id == current_user.id))
    ).all()

    context = dict(
        clients=clients
    )
    return render_template('clients/list.html', **context)


@blueprint.route('/new', methods=('POST', 'GET'))
@manager_required
def new():
    form = ClientForm(request.form)

    form.managers.choices = User.get_choices(User.user_type.in_(valid_managers))
    form.auditors.choices = User.get_choices(User.user_type.in_(valid_auditors))

    context = dict(
        form=form
    )
    if form.validate_on_submit():
        data = form.data
        data.pop('csrf_token')

        Client(
            creator=current_user,
            **data
        )
        return redirect_back('.index')

    return render_template('clients/new.html', **context)


@blueprint.route('/delete/<client_id>', methods=('POST',))
@manager_required
def delete(client_id: int):
    client = Client.query.filter_by(id=client_id).one()

    if not current_user.owns(client):
        abort(403)

    client.delete()

    return redirect_back('.index')


@blueprint.route('/<client_id>/change_owner', methods=('POST',))
def change_owner(client_id: int):
    client: Client = Client.query.filter_by(id=client_id).one()

    if not current_user.owns(client):
        abort(403)

    form = ClientChangeOwnerForm()
    form.owner.choices = User.get_choices(User.user_type.in_(valid_managers))

    if form.validate_on_submit():
        client.creator = form.owner.data

    return redirect_back('.index')


@blueprint.route('/<client_id>', methods=('POST', 'GET'))
@manager_required
def edit(client_id: int):
    client: Client = Client.query.filter_by(id=client_id).one()

    if not current_user.manages(client):
        abort(403)

    if request.form:
        form = ClientForm(request.form)
    else:
        form = ClientForm(**client.to_dict(), managers=client.managers, auditors=client.auditors)

    form.managers.choices = User.get_choices(User.user_type.in_(valid_managers))
    form.auditors.choices = User.get_choices(User.user_type.in_(valid_auditors))

    change_owner_form = ClientChangeOwnerForm(owner=client.creator)
    change_owner_form.owner.choices = User.get_choices(User.user_type.in_(valid_managers))

    context = dict(
        form=form,
        change_owner_form=change_owner_form,
        client=client
    )
    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        managers = data.pop('managers', [])
        auditors = data.pop('auditors', [])

        client.set(**data)

        client.managers.clear()
        client.managers.extend(managers)

        client.auditors.clear()
        client.auditors.extend(auditors)

        return redirect_back('.index')
    return render_template('clients/details.html', **context)


@blueprint.route('/<client_id>/add_assessment', methods=('POST', 'GET'))
@manager_required
def add_assessment(client_id: int):
    client = Client.query.filter_by(id=client_id).one()

    if not current_user.audits(client):
        abort(403)

    form = AssessmentForm(request.form)
    form.auditors.choices = User.get_choices(User.user_type.in_(valid_auditors))
    context = dict(
        form=form,
        client=client
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)

        Assessment(client=client, creator=current_user, **data)
        return redirect_back('.edit', client_id=client_id)
    return render_template('clients/add_assessment.html', **context)


@blueprint.route('/<client_id>/add_template', methods=('POST', 'GET'))
@manager_required
def add_template(client_id: int):
    client = Client.query.filter_by(id=client_id).one()

    if not current_user.manages(client):
        abort(403)

    form = TemplateCreateNewForm()
    context = dict(
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
            db.session.commit()
            file.save(os.path.join(upload_path, filename))
            return redirect_back('.edit', client_id=client_id)
        except IntegrityError:
            form.name.errors.append('Name already used')
            db.session.rollback()

    return render_template('clients/add_template.html', **context)


@blueprint.route('/<client_id>/template/<template_name>/delete', methods=('POST',))
@manager_required
def delete_template(client_id: int, template_name):
    client = Client.query.filter_by(id=client_id).one()
    if not current_user.manages(client):
        abort(403)

    template = Template.query.filter_by(name=template_name, client=client).one()
    os.remove(os.path.join(client.template_path(), template.file))
    template.delete()
    return redirect_back('.edit', client_id=client_id)


@blueprint.route('/<client_id>/template/<template_name>/download')
@manager_required
def download_template(client_id: int, template_name):
    client = Client.query.filter_by(id=client_id).one()
    if not current_user.manages(client):
        abort(403)

    template = Template.query.filter_by(name=template_name, client=client).one()
    return send_from_directory(
        client.template_path(),
        template.file,
        as_attachment=True,
        attachment_filename="{}.{}".format(template.name, template.file.split('.')[-1])
    )
