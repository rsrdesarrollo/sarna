import os
from datetime import datetime
from uuid import uuid4

from flask import Blueprint, render_template, send_from_directory, request
from sqlalchemy.exc import IntegrityError

from sarna.auxiliary import redirect_back
from sarna.core.roles import manager_required
from sarna.forms.templates import TemplateCreateNewForm, TemplateEditForm
from sarna.model import Template, db

blueprint = Blueprint('templates', __name__)


@blueprint.route('/')
@manager_required
def index():
    context = dict(
        templates=Template.query.all()
    )
    return render_template('templates/list.html', **context)


@blueprint.route('/new', methods=('POST', 'GET'))
@manager_required
def new():
    form = TemplateCreateNewForm()

    context = dict(
        form=form
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token')

        file = data.pop('file')
        filename = "{}.{}".format(uuid4(), file.filename.split('.')[-1])

        data['file'] = filename
        upload_path = Template.template_path()
        if not os.path.exists(upload_path):
            os.makedirs(upload_path)

        try:
            db.session.add(Template(**data))
            db.session.commit()
            file.save(os.path.join(upload_path, filename))
            return redirect_back('.index')
        except IntegrityError:
            form.name.errors.append('Name already used')
            db.session.rollback()

    return render_template('templates/new.html', **context)


@blueprint.route('/delete/<template_id>', methods=('POST',))
@manager_required
def delete(template_id: int):
    template = Template.query.filter_by(id=template_id).one()

    os.remove(os.path.join(template.template_path(), template.file))
    template.delete()

    return redirect_back('.index')


@blueprint.route('/edit/<template_id>', methods=('POST', 'GET'))
@manager_required
def edit(template_id: int):
    template = Template.query.filter_by(id=template_id).one()
    form = TemplateEditForm()

    if not request.form:
        form = TemplateEditForm(**template.to_dict())

    context = dict(
        template=template,
        form=form
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)

        file = data.pop('file')

        try:
            template.set(**data)
            template.last_modified = datetime.now()
            db.session.commit()

            if file is not None:
                file.save(os.path.join(template.template_path(), template.file))

            return redirect_back('.index')
        except IntegrityError:
            form.name.errors.append('Name already used')
            db.session.rollback()

    return render_template('templates/edit.html', **context)


@blueprint.route('/download/<template_id>')
@manager_required
def download(template_id: int):
    template = Template.query.filter_by(id=template_id).one()
    return send_from_directory(
        template.template_path(),
        template.file,
        as_attachment=True,
        attachment_filename="{}.template.{}".format(template.name, template.file.split('.')[-1])
    )
