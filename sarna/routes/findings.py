from flask import Blueprint, render_template, redirect, url_for, request, flash
from sarna.model import FindingTemplate
from sarna.model import db_session, select
from sarna.forms import *
from sarna.model.aux import Language

import os

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('findings', __name__)


@blueprint.route('/')
@db_session()
def index():
    context = dict(
        route=ROUTE_NAME,
        findings=select(elem for elem in FindingTemplate)
    )
    return render_template('findings/list.html', **context)


@blueprint.route('/new', methods=('GET', 'POST'))
@db_session()
def new():
    form = FindingTemplateCreateNewForm(request.form)
    context = dict(
        route=ROUTE_NAME,
        form=form
    )
    if form.validate_on_submit():
        data = dict(form.data)

        data_finding = {k: v for k, v in data.items() if k in FindingTemplate._adict_}
        data_translation = {k: v for k, v in data.items() if k in FindingTemplateTranslation._adict_}

        finding = FindingTemplate(**data_finding)
        FindingTemplateTranslation(finding=finding, **data_translation)
        return redirect(url_for('.index'))

    return render_template('findings/new.html', **context)


@blueprint.route('/<finding_id>', methods=('POST', 'GET'))
@db_session()
def edit(finding_id: int):
    finding = FindingTemplate[finding_id]

    form_data = request.form.to_dict() or finding.to_dict()
    form = FindingTemplateEditForm(**form_data)
    context = dict(
        route=ROUTE_NAME,
        form=form,
        finding=finding
    )
    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        finding.set(**data)
        return redirect(url_for('.index'))
    return render_template('findings/details.html', **context)


@blueprint.route('/<finding_id>/delete', methods=('POST',))
@db_session()
def delete(finding_id: int):
    FindingTemplate[finding_id].delete()
    return redirect(url_for('.index'))


@blueprint.route('/<finding_id>/add_translation', methods=('POST', 'GET'))
@db_session()
def add_translation(finding_id: int):
    finding = FindingTemplate[finding_id]
    form = FindingTemplateAddTranslationForm(request.form)

    # Skip langs already presents
    form.lang.choices = tuple(
        choice for choice in Language.choices() if choice[0] not in finding.langs
    )

    context = dict(
        route=ROUTE_NAME,
        form=form,
        finding=finding
    )

    if len(form.lang.choices) == 0:
        flash('Finding {} already have all possible translations.'.format(finding.name), category='warning')
        return redirect(url_for('.index'))

    if form.validate_on_submit():
        if form.lang.data not in finding.langs:
            data = dict(form.data)
            data.pop('csrf_token', None)

            FindingTemplateTranslation(finding=finding, **data)
        else:
            flash('Language {} already created for this finding.'.format(form.lang.data), category='danger')

        return redirect(url_for('.index'))

    return render_template('findings/edit_translation.html', **context)


@blueprint.route('/<finding_id>/delete/<language>', methods=('POST',))
@db_session()
def delete_translation(finding_id: int, language: str):
    FindingTemplateTranslation[finding_id, Language[language]].delete()
    return redirect(url_for('.edit', finding_id=finding_id))


@blueprint.route('/<finding_id>/edit/<language>', methods=('POST', 'GET'))
@db_session()
def edit_translation(finding_id: int, language: str):
    language = Language[language]
    translation = FindingTemplateTranslation[finding_id, language]

    form_data = request.form.to_dict() or translation.to_dict(with_lazy=True)
    form = FindingTemplateEditTranslationForm(**form_data)

    context = dict(
        route=ROUTE_NAME,
        form=form,
        finding=translation.finding
    )

    if form.validate_on_submit():
        if language in translation.finding.langs:
            data = dict(form.data)
            data.pop('csrf_token', None)
            translation.set(**data)
        else:
            flash('Language {} not created for this finding.'.format(language), category='danger')

        return redirect(url_for('.edit', finding_id=finding_id))

    return render_template('findings/edit_translation.html', **context)


@blueprint.route('/<finding_id>/add_solution', methods=('POST', 'GET'))
@db_session()
def add_solution(finding_id: int):
    finding = FindingTemplate[finding_id]
    form = FindingTemplateAddSolutionForm(request.form)

    context = dict(
        route=ROUTE_NAME,
        form=form,
        finding=finding
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        lang = data.get('lang')
        name = data.get('name')

        try:
            Solution(finding_template=finding, **data)
            commit()
            return redirect(url_for('.index'))
        except TransactionIntegrityError:
            error = 'Solution name {} already exist for this finding.'.format(name, lang)
            form.name.errors.append(error)

    return render_template('findings/edit_solution.html', **context)


@blueprint.route('/<finding_id>/solution/<solution_name>/delete', methods=('POST',))
@db_session()
def delete_solution(finding_id: int, solution_name: str):
    Solution[finding_id, solution_name].delete()
    return redirect(url_for('.edit', finding_id=finding_id))


@blueprint.route('/<finding_id>/solution/<solution_name>', methods=('POST', 'GET'))
@db_session()
def edit_solution(finding_id: int, solution_name: str):
    solution = Solution[finding_id, solution_name]

    form_data = request.form.to_dict() or solution.to_dict(with_lazy=True)
    form = FindingTemplateEditSolutionForm(**form_data)

    context = dict(
        route=ROUTE_NAME,
        form=form,
        finding=solution.finding_template
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        solution.set(**data)

        return redirect(url_for('.edit', finding_id=finding_id))

    return render_template('findings/edit_solution.html', **context)


