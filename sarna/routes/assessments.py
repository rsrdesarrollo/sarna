import os

from flask import Blueprint, render_template, redirect, url_for, request, flash, send_from_directory
from flask import abort
from werkzeug.utils import secure_filename

from sarna import limiter
from sarna.aux import redirect_referer
from sarna.forms import AssessmentForm
from sarna.forms import FindingEditForm, BulkActionForm, ActiveCreateNewForm, EvidenceCreateNewForm
from sarna.model import Assessment, AffectedResource, Finding, Solution, FindingTemplate, FindingStatus, Active
from sarna.model import Image, Template
from sarna.model import db_session, select, commit, TransactionIntegrityError
from sarna.report_generator.engine import generate_reports_bundle

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


@blueprint.route('/<assessment_id>/delete', methods=('POST',))
@db_session()
def delete(assessment_id):
    Assessment[assessment_id].delete()
    return redirect_referer(url_for('.index'))


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


@blueprint.route('/<assessment_id>/findings/<finding_id>/delete', methods=('POST',))
@db_session()
def delete_findings(assessment_id, finding_id):
    Finding[finding_id].delete()
    flash("Findign deleted", "success")
    return redirect_referer(url_for('.findings', assessment_id=assessment_id))


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
    # TODO: Change to POST
    assessment = Assessment[assessment_id]
    template = FindingTemplate[finding_id]

    finding = Finding.build_from_template(template, assessment)
    flash('Finding {} added successfully'.format(finding.name), 'success')

    return redirect_referer(url_for('.add_findings', assessment_id=assessment.id))


@blueprint.route('/<assessment_id>/edit_add/<finding_id>')
@db_session()
def edit_add_finding(assessment_id, finding_id):
    assessment = Assessment[assessment_id]
    template = FindingTemplate[finding_id]

    finding = Finding.build_from_template(template, assessment)

    try:
        commit()
    except:
        flash('Error ading finding {}'.format(finding.name), 'danger')
        return redirect_referer(url_for('add_findings', assessment_id=assessment.id))

    flash('Finding {} added successfully'.format(finding.name), 'success')

    return redirect(url_for('.edit_finding', assessment_id=assessment.id, finding_id=finding.id))


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

    return redirect_referer(url_for('.findings', assessment_id=assessment_id))


@blueprint.route('/<assessment_id>/actives', methods=("POST", "GET"))
@db_session()
def actives(assessment_id):
    assessment = Assessment[assessment_id]
    form = ActiveCreateNewForm(request.form)
    actives = assessment.actives.order_by(Active.name)
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment,
        actives=actives,
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
@limiter.exempt
@db_session()
def evidences(assessment_id):
    assessment = Assessment[assessment_id]
    form = EvidenceCreateNewForm()
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    if form.is_submitted():
        if form.validate_on_submit():
            upload_path = assessment.evidence_path()

            if not os.path.exists(upload_path):
                os.makedirs(upload_path)

            file = form.file.data
            try:
                filename = secure_filename(file.filename)
                Image(assessment=assessment, name=filename)
                commit()
                file.save(os.path.join(upload_path, filename))
            except TransactionIntegrityError:
                return "Duplicate image name {}".format(filename), 400
            return "OK", 200
        else:
            return "Invalid file", 400
    return render_template('assessments/panel/evidences.html', **context)


@blueprint.route('/<assessment_id>/evidences/<evidence_name>')
@limiter.exempt
@db_session()
def get_evidence(assessment_id, evidence_name):
    assessment = Assessment[assessment_id]
    image = Image[assessment, evidence_name]

    return send_from_directory(
        assessment.evidence_path(),
        image.name,
        mimetype='image/jpeg'
    )


@blueprint.route('/<assessment_id>/reports')
@db_session()
def reports(assessment_id):
    assessment = Assessment[assessment_id]
    context = dict(
        route=ROUTE_NAME,
        endpoint=request.url_rule.endpoint.split('.')[-1],
        assessment=assessment
    )
    return render_template('assessments/panel/reports.html', **context)


@blueprint.route('/<assessment_id>/reports/download', methods=('POST',))
@db_session()
def download_reports(assessment_id):
    assessment = Assessment[assessment_id]
    data = request.form.to_dict()
    data.pop('action', None)
    data.pop('csrf_token', None)
    data.pop('template:all', None)

    templates = set()
    for k, v in data.items():
        if k.startswith('template'):
            try:
                template_name = k.split(':')[1]
                templates.add(Template[assessment.client, template_name])
            except:
                continue

    if not templates:
        flash('No report selected', 'danger')
        return redirect(url_for('.reports', assessment_id=assessment_id))

    report_path, report_file = generate_reports_bundle(assessment, templates)
    return send_from_directory(
        report_path,
        report_file,
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=report_file,
    )


@blueprint.route('/<assessment_id>/reports/download/<template_name>', methods=('GET',))
@db_session()
def download_report(assessment_id, template_name):
    assessment = Assessment[assessment_id]
    template = Template[assessment.client, template_name]
    report_path, report_file = generate_reports_bundle(assessment, [template])
    return send_from_directory(
        report_path,
        report_file,
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=report_file,
    )
