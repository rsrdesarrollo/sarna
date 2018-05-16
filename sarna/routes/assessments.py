from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, send_from_directory
from flask import abort
from sarna import config
from sarna.aux import upload_helpers
from sarna.model import *
from sarna.model import db_session, select, commit, TransactionIntegrityError
from sarna.forms import AssessmentForm
from sarna.forms import FindingEditForm, BulkActionForm, ActiveCreateNewForm
from werkzeug.utils import secure_filename

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


@blueprint.route('/<assessment_id>/findings/resource/<affected_resource_id>')
@blueprint.route('/<assessment_id>/findings')
@db_session()
def findings(assessment_id, finding_id=None, affected_resource_id=None):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint='findings',
        assessment=assessment
    )

    if affected_resource_id is not None:
        affected = AffectedResource[affected_resource_id]
        if affected.active.assessment != assessment:
            return abort(401)

        findings = affected.findings
    else:
        findings = assessment.findings.order_by(Finding.id)

    context['form'] = BulkActionForm()
    context['findings'] = findings
    return render_template('assessments/panel/list_findings.html', **context)


@blueprint.route('/<assessment_id>/findings/<finding_id>', methods=('GET', 'POST'))
@db_session()
def edit_finding(assessment_id, finding_id):
    assessment = Assessment[assessment_id]
    finding = Finding[finding_id]

    form_data = request.form.to_dict() or finding.to_dict(with_lazy=True)
    form = FindingEditForm(**form_data)
    context = dict(
        route=ROUTE_NAME,
        endpoint='findings',
        assessment=assessment,
        form=form,
        finding=finding,
        solutions=finding.template.solutions.order_by(Solution.name),
        solutions_dict={
            a.name: a.text
            for a in finding.template.solutions
        }
    )
    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        finding.set(**data)
        return redirect(url_for('.findings', assessment_id=assessment_id))

    return render_template('assessments/panel/edit_finding.html', **context)


@blueprint.route('/<assessment_id>/findings/<finding_id>/delete')
@db_session()
def delete_findings(assessment_id, finding_id):
    Finding[finding_id].delete()
    flash("Findign deleted", "success")
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
    form = FindingEditForm()

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
    form = ActiveCreateNewForm(request.form)
    actives = assessment.actives.order_by(Active.name)
    actives_dict = [dict(name=a.name) for a in actives]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment,
        actives=actives,
        actives_dict=actives_dict,
        form=form
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        try:
            active = Active[data['name']]
        except:
            active = Active(name=data['name'], assessment=assessment)

        AffectedResource(active=active, route=data['route'])

        return redirect(url_for('.actives', assessment_id=assessment_id))

    return render_template('assessments/panel/list_actives.html', **context)


@blueprint.route('/<assessment_id>/evidences', methods=("POST", "GET"))
@db_session()
def evidences(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    if request.method == 'POST':
        upload_path = os.path.join(config.UPLOAD_PATH, "{}-{}".format(
            secure_filename(assessment.name),
            assessment.uuid
        ))
        if not os.path.exists(upload_path):
            os.makedirs(upload_path)

        if 'file' not in request.files:
            return "No Selected file", 400

        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        if file and upload_helpers.is_valid_evidence(file):
            try:
                filename = secure_filename(file.filename)
                Image(assessment=assessment, name=filename)
                commit()
                file.save(os.path.join(upload_path, filename))
            except TransactionIntegrityError as ex:
                return "Duplicate image name {}".format(filename), 400

            return "OK", 200
        else:
            return "Invalid file", 400
    return render_template('assessments/panel/evidences.html', **context)


@blueprint.route('/<assessment_id>/evidences/<evidence_name>')
@db_session()
def get_evidence(assessment_id, evidence_name):
    assessment = Assessment[assessment_id]
    image = Image[assessment, evidence_name]

    upload_path = os.path.join(config.UPLOAD_PATH, "{}-{}".format(
        secure_filename(assessment.name),
        assessment.uuid
    ))
    return send_from_directory(upload_path, image.name, mimetype='image/jpeg')


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
