from flask import Blueprint, render_template, request, flash, abort
from sqlalchemy.exc import IntegrityError

from sarna.auxiliary import redirect_back
from sarna.core.auth import current_user
from sarna.core.roles import trusted_required
from sarna.forms.finding_template import *
from sarna.model import FindingTemplate, FindingTemplateTranslation, db
from sarna.model.enums import Language
from sarna.model.finding_template import Solution

blueprint = Blueprint('findings', __name__)


@blueprint.route('/')
@trusted_required
def index():
    context = dict(
        findings=FindingTemplate.query.all()
    )
    return render_template('findings/list.html', **context)


@blueprint.route('/new', methods=('GET', 'POST'))
@trusted_required
def new():
    form = FindingTemplateCreateNewForm(request.form)
    context = dict(
        form=form
    )
    if form.validate_on_submit():
        data = dict(form.data)

        data_finding = {k: v for k, v in data.items() if k in FindingTemplate.__dict__}
        data_translation = {k: v for k, v in data.items() if k in FindingTemplateTranslation.__dict__}

        finding = FindingTemplate(creator=current_user, **data_finding)
        FindingTemplateTranslation(finding_template=finding, **data_translation)
        return redirect_back('.index')

    return render_template('findings/new.html', **context)


@blueprint.route('/<finding_id>', methods=('POST', 'GET'))
@trusted_required
def edit(finding_id: int):
    finding = FindingTemplate.query.filter_by(id=finding_id).one()

    form_data = request.form.to_dict() or finding.to_dict()
    form = FindingTemplateEditForm(**form_data)
    context = dict(
        form=form,
        finding=finding
    )
    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        finding.set(**data)
        db.session.commit()
        return redirect_back('.index')
    return render_template('findings/details.html', **context)


@blueprint.route('/<finding_id>/delete', methods=('POST',))
@trusted_required
def delete(finding_id: int):
    finding_template = FindingTemplate.query.filter_by(id=finding_id).one()
    finding_template.delete()
    return redirect_back('.index')


@blueprint.route('/<finding_id>/add_translation', methods=('POST', 'GET'))
@trusted_required
def add_translation(finding_id: int):
    finding = FindingTemplate.query.filter_by(id=finding_id).one()
    form = FindingTemplateAddTranslationForm(request.form)

    current_langs = finding.langs
    # Skip langs already presents
    form.lang.choices = tuple(
        choice for choice in Language.choices() if choice[0] not in current_langs
    )

    context = dict(
        form=form,
        finding=finding
    )

    if len(form.lang.choices) == 0:
        flash('Finding {} already have all possible translations.'.format(finding.name), category='warning')
        return redirect_back('.index')

    if form.validate_on_submit():
        if form.lang.data not in finding.langs:
            data = dict(form.data)
            data.pop('csrf_token', None)

            FindingTemplateTranslation(finding_template=finding, **data)
        else:
            flash('Language {} already created for this finding.'.format(form.lang.data), category='danger')

        return redirect_back('.index')

    return render_template('findings/edit_translation.html', **context)


@blueprint.route('/<finding_id>/delete/<language>', methods=('POST',))
@trusted_required
def delete_translation(finding_id: int, language: str):
    tranlsation = FindingTemplateTranslation.query.filter_by(
        finding_template_id=finding_id,
        lang=Language[language]
    ).one()

    tranlsation.delete()
    return redirect_back('.edit', finding_id=finding_id)


@blueprint.route('/<finding_id>/edit/<language>', methods=('POST', 'GET'))
@trusted_required
def edit_translation(finding_id: int, language: str):
    language = Language[language]
    translation = FindingTemplateTranslation.query.filter_by(
        finding_template_id=finding_id,
        lang=language
    ).one()

    form_data = request.form.to_dict() or translation.to_dict()
    form = FindingTemplateEditTranslationForm(**form_data)

    context = dict(
        form=form,
        finding=translation.finding_template
    )

    if form.validate_on_submit():
        if language in translation.finding_template.langs:
            data = dict(form.data)
            data.pop('csrf_token', None)
            translation.set(**data)
        else:
            flash('Language {} not created for this finding.'.format(language), category='danger')

        return redirect_back('.edit', finding_id=finding_id)

    return render_template('findings/edit_translation.html', **context)


@blueprint.route('/<finding_id>/add_solution/<solution_name>', methods=('POST', 'GET'))
@blueprint.route('/<finding_id>/add_solution', methods=('POST', 'GET'))
@trusted_required
def add_solution(finding_id: int, solution_name=None):
    finding = FindingTemplate.query.filter_by(id=finding_id).one()
    solution = None
    if solution_name:
        solution = Solution.query.filter_by(
            finding_template_id=finding_id,
            name=solution_name
        ).one()

    form_data = solution.to_dict() if solution else request.form.to_dict()
    form = FindingTemplateAddSolutionForm(**form_data)

    context = dict(
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
            db.session.commit()
            return redirect_back('.index')
        except IntegrityError:
            db.session.rollback()
            error = 'Solution name {} already exist for this finding.'.format(name, lang)
            form.name.errors.append(error)

    return render_template('findings/edit_solution.html', **context)


@blueprint.route('/<finding_id>/solution/<solution_name>/delete', methods=('POST',))
@trusted_required
def delete_solution(finding_id: int, solution_name: str):
    solution = Solution.query.filter_by(
        finding_template_id=finding_id,
        name=solution_name
    ).one()
    solution.delete()
    return redirect_back('.edit', finding_id=finding_id)


@blueprint.route('/<finding_id>/solution/<solution_name>', methods=('POST', 'GET'))
@trusted_required
def edit_solution(finding_id: int, solution_name: str):
    solution = Solution.query.filter_by(
        finding_template_id=finding_id,
        name=solution_name
    ).one()

    form_data = request.form.to_dict() or solution.to_dict()
    form = FindingTemplateEditSolutionForm(**form_data)

    context = dict(
        form=form,
        finding=solution.finding_template
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        solution.set(**data)

        return redirect_back('.edit', finding_id=finding_id)

    return render_template('findings/edit_solution.html', **context)
