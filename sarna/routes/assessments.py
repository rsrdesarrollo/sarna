from flask import Blueprint, render_template, redirect, url_for, request, flash
from sarna.model import Assessment, FindingTemplate, Finding, FindingStatus
from sarna.model import db_session, select
from sarna.forms import AssessmentForm
from sarna.forms import FindingCreateNewForm, BulkActionForm

import os

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('assessments', __name__)


@blueprint.route('/')
@db_session()
def index():
    context = dict(
        route=ROUTE_NAME,
        assessments=select(assessment for assessment in Assessment)
    )
    return render_template('assessments/list.html', **context)


@blueprint.route('/<assessment_id>', methods=('GET', 'POST'))
@db_session()
def edit(assessment_id):
    assessment = Assessment[assessment_id]
    form_data = request.form.to_dict() or assessment.to_dict()

    form = AssessmentForm(**form_data)

    context = dict(
        route=ROUTE_NAME,
        assessment=assessment,
        form=form
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        assessment.set(**data)

        return redirect(url_for('.index'))

    return render_template('assessments/edit.html', **context)


@blueprint.route('/<assessment_id>/delete')
@db_session()
def delete(assessment_id):
    Assessment[assessment_id].delete()
    return redirect(url_for('.index'))


@blueprint.route('/<assessment_id>/summary')
@db_session()
def summary(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    return render_template('assessments/panel/summary.html', **context)


@blueprint.route('/<assessment_id>/findings')
@db_session()
def findings(assessment_id):
    assessment = Assessment[assessment_id]
    form = BulkActionForm()
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment,
        findings=assessment.findings.order_by(Finding.id),
        form=form
    )
    return render_template('assessments/panel/list_findings.html', **context)


@blueprint.route('/<assessment_id>/findings/<finding_id>')
@db_session()
def edit_findings(assessment_id, finding_id):
    pass


@blueprint.route('/<assessment_id>/findings/<finding_id>/delete')
@db_session()
def delete_findings(assessment_id, finding_id):
    Finding[finding_id].delete()
    flash("Findign deleted", "info")
    return redirect(url_for('.findings', assessment_id=assessment_id))


@blueprint.route('/<assessment_id>/add')
@db_session()
def add_findings(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment,
        findings=select(elem for elem in FindingTemplate)
    )
    return render_template('assessments/panel/add_finding.html', **context)


@blueprint.route('/<assessment_id>/add/<finding_id>')
@db_session()
def add_finding(assessment_id, finding_id):
    assessment = Assessment[assessment_id]
    template = FindingTemplate[finding_id]

    finding = Finding.build_from_template(template, assessment)
    flash('Finding {} added successfully'.format(finding.name), 'success')

    return redirect(url_for('.add_findings', assessment_id=assessment.id))


@blueprint.route('/<assessment_id>/edit_add/<finding_id>')
@db_session()
def edit_add_finding(assessment_id, finding_id):
    assessment = Assessment[assessment_id]
    template = FindingTemplate[finding_id]
    form = FindingCreateNewForm()

    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment,
        form=form
    )

    return render_template('assessments/panel/edit_finding.html', **context)


@blueprint.route('/<assessment_id>/bulk_action', methods=("POST",))
@db_session()
def bulk_action_finding(assessment_id):
    data = request.form.to_dict()
    action = data.pop('action', None)
    data.pop('csrf_token', None)
    data.pop('finding:all', None)

    findings = set()
    for k, v in data.items():
        if k.startswith('finding'):
            try:
                findings.add(int(k.split(':')[1]))
            except:
                continue

    target = select(elem for elem in Finding if elem.id in findings)
    if action == "delete":
        target.delete(bulk=True)
        flash("{} items deleted successfully.".format(len(findings)), "success")
    elif action.startswith('status_'):
        status = None
        if action == "status_pending":
            status = FindingStatus.Pending
        elif action == "status_reviewed":
            status = FindingStatus.Reviewed
        elif action == "status_confirmed":
            status = FindingStatus.Confirmed
        elif action == "status_false_positive":
            status = FindingStatus.False_Positive
        elif action == "status_other":
            status = FindingStatus.Other

        for elem in target:
            elem.status = status

        flash("{} items set to {} status successfully.".format(len(findings), status.name), "success")

    return redirect(url_for('.findings', assessment_id=assessment_id))


@blueprint.route('/<assessment_id>/actives', methods=("POST", "GET"))
@db_session()
def actives(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    return render_template('assessments/panel/blank.html', **context)


@blueprint.route('/<assessment_id>/evidences', methods=("POST", "GET"))
@db_session()
def evidences(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    return render_template('assessments/panel/blank.html', **context)


@blueprint.route('/<assessment_id>/reports', methods=("POST", "GET"))
@db_session()
def reports(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    return render_template('assessments/panel/blank.html', **context)
