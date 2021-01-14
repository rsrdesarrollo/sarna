import os

from PIL import Image as PillowImage
from flask import Blueprint, render_template, request, flash, send_from_directory, Response
from flask import abort
from sqlalchemy import and_
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename

from sarna.auxiliary import redirect_back, redirect_endpoint
from sarna.bugtracking.jira import JiraAPI
from sarna.core.auth import current_user
from sarna.core.roles import auditor_required, trusted_required, manager_required, assessment_allowed
from sarna.core.security import limiter
from sarna.forms.assessment import AssessmentForm, FindingEditForm, EvidenceCreateNewForm
from sarna.model import Assessment, Finding, FindingTemplate, db, Image, Template, \
    Client
from sarna.model.enums import FindingStatus
from sarna.report_generator.engine import generate_reports_bundle

blueprint = Blueprint('assessments', __name__)


@blueprint.route('/')
@trusted_required
def index():
    context = dict(
        assessments=current_user.get_user_assessments()
    )
    return render_template('assessments/list.html', **context)


@blueprint.route('/<assessment_id>', methods=['GET'])
@auditor_required
@assessment_allowed
def detail(**kwargs):
    assessment: Assessment = kwargs['assessment']
    form = AssessmentForm(**assessment.to_dict(), auditors=assessment.auditors)
    form.auditors.choices = assessment.client.get_auditor_choices()

    context = dict(
        assessment=assessment,
        form=form
    )    
    return render_template('assessments/edit.html', **context)


@blueprint.route('/<assessment_id>', methods=['POST'])
@manager_required
@assessment_allowed
def edit(**kwargs):
    assessment: Assessment = kwargs['assessment']

    form = AssessmentForm(request.form)
    form.auditors.choices = assessment.client.get_auditor_choices()

    context = dict(
        assessment=assessment,
        form=form
    )

    if form.validate_on_submit():
        data = dict(form.data)
        data.pop('csrf_token', None)
        auditors = data.pop('auditors', [])

        assessment.set(**data)
        assessment.auditors.clear()
        assessment.auditors.extend(auditors)

        return redirect_back('.index')

    return render_template('assessments/edit.html', **context)


@blueprint.route('/<assessment_id>/export', methods=('GET',))
@assessment_allowed
def export(**kwargs):
    assessment: Assessment = kwargs['assessment']

    return Response(
        assessment.to_json(max_nesting=5),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename=assessment-{assessment_id}.json'}
    )


@blueprint.route('/<assessment_id>/delete', methods=('POST',))
@auditor_required
@assessment_allowed
def delete(**kwargs):
    assessment = kwargs['assessment']
    assessment.delete()
    return redirect_back('.index')


@blueprint.route('/<assessment_id>/summary')
@trusted_required
@assessment_allowed
def summary(**kwargs):
    context = dict(
        assessment=kwargs['assessment']
    )
    return render_template('assessments/panel/summary.html', **context)


@blueprint.route('/<assessment_id>/findings')
@trusted_required
@assessment_allowed
def findings(**kwargs):
    context = dict(
        assessment=kwargs['assessment']
    )

    return render_template('assessments/panel/list_findings.html', **context)


@blueprint.route('/<assessment_id>/findings/<finding_id>/detail', methods=('GET',))
@trusted_required
@assessment_allowed
def detail_finding(**kwargs):
    finding = kwargs.get('finding')
    assessment = kwargs.get('assessment')

    context = dict(
        finding=finding,
        assessment=assessment
    )
    return render_template('assessments/panel/finding_detail.html', **context)


@blueprint.route('/<assessment_id>/findings/<finding_id>', methods=('GET', 'POST'))
@auditor_required
@assessment_allowed
def edit_finding(**kwargs):
    assessment = kwargs['assessment']
    finding = kwargs['finding']

    solutions = finding.template.solutions if finding.template else []
    context = dict(
            assessment=assessment,
            finding=finding,
            evidences=assessment.images,
            bugtracking_url=os.getenv('JIRA_SERVER') + '/projects/',
            solutions=solutions,
            solutions_dict={
                a.name: a.text
                for a in solutions
            }
        )

    if request.method == 'GET':
        finding_dict = finding.to_dict()
        finding_dict['affected_resources'] = "\r\n".join(r.uri for r in finding.affected_resources)
        finding_dict = finding.display_one_to_manies(finding_dict)
        context['form'] = FindingEditForm(**finding_dict)
    else:
        form = FindingEditForm(request.form)
        context['form'] = form
        if form.validate_on_submit():
            data = dict(form.data)
            data.pop('csrf_token', None)
            affected_resources = data.pop('affected_resources', '').split('\n')
            try:
                finding.update_affected_resources(affected_resources)  # TODO: Raise different exception
                finding.update_one_to_manies(form)
                finding.set(**data)
                return redirect_back('.findings', assessment_id=kwargs['assessment_id'])
            except ValueError as ex:
                form.affected_resources.errors.append(str(ex))
    
    return render_template('assessments/panel/edit_finding.html', **context)


@blueprint.route('/<assessment_id>/findings/<finding_id>/delete', methods=('POST',))
@auditor_required
@assessment_allowed
def delete_findings(**kwargs):
    finding = kwargs['finding']

    finding.update_affected_resources([])
    finding.delete()
    flash("Finding deleted", "success")
    return redirect_back('.findings', assessment_id=kwargs['assessment_id'])


@blueprint.route('/<assessment_id>/findings/<finding_id>/report', methods=('GET', 'POST'))
@auditor_required
def report_finding(**kwargs):
    finding = kwargs['finding']

    JiraAPI().create_finding(finding)

    return redirect_back('.findings', assessment_id=kwargs['assessment_id'])


@blueprint.route('/<assessment_id>/add')
@auditor_required
@assessment_allowed
def add_findings(**kwargs):
    context = dict(
        assessment=kwargs['assessment'],
        findings=FindingTemplate.query.all()
    )
    return render_template('assessments/panel/add_finding.html', **context)


@blueprint.route('/<assessment_id>/add/<template_id>', methods=('POST',))
@auditor_required
@assessment_allowed
def add_finding(**kwargs):
    action = request.form.get('action', None)
    if not action or action not in {'add', 'edit_add'}:
        abort(400)

    assessment = kwargs['assessment']
    template = FindingTemplate.query.filter_by(id=kwargs['template_id']).one()

    finding = Finding.build_from_template(template, assessment)

    db.session.commit()
    flash('Finding {} added successfully'.format(finding.name), 'success')

    if action == 'edit_add':
        return redirect_endpoint('.edit_finding', assessment_id=assessment.id, finding_id=finding.id)

    return redirect_back('.add_findings', assessment_id=assessment.id)


@blueprint.route('/<assessment_id>/bulk_action', methods=("POST",))
@auditor_required
@assessment_allowed
def bulk_action_finding(**kwargs):
    data = request.form.to_dict()
    action = data.pop('action', None)
    data.pop('csrf_token', None)

    assessment = kwargs['assessment']

    set_findings = set(request.form.getlist('finding_id'))

    target = Finding.query.filter(
        and_(Finding.id.in_(set_findings), Finding.assessment == assessment)
    )
    if action == "delete":
        for finding in target:
            finding.update_affected_resources([])

        target.delete(synchronize_session=False)

        flash("{} items deleted successfully.".format(len(set_findings)), "success")
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

        db.session.commit()
        flash("{} items set to {} status successfully.".format(len(set_findings), status.name), "success")

    return redirect_back('.findings', assessment_id=kwargs['assessment_id'])


@blueprint.route('/<assessment_id>/actives', methods=("GET",))
@trusted_required
@assessment_allowed
def actives(**kwargs):
    assessment = kwargs['assessment']

    list_actives = assessment.actives
    context = dict(
        assessment=assessment,
        actives=list_actives
    )

    return render_template('assessments/panel/list_actives.html', **context)


@blueprint.route('/<assessment_id>/evidences', methods=("POST", "GET"))
@limiter.exempt
@auditor_required
@assessment_allowed
def evidences(**kwargs):
    assessment = kwargs['assessment']

    form = EvidenceCreateNewForm()
    context = dict(
        assessment=assessment
    )
    if form.is_submitted():
        if form.validate_on_submit():
            upload_path = assessment.evidence_path()

            try:
                os.makedirs(upload_path)
            except FileExistsError:
                pass

            file = form.file.data
            filename = secure_filename(file.filename)
            try:
                Image(assessment=assessment, name=filename)
                db.session.commit()

                img = PillowImage.open(file)
                img.save(os.path.join(upload_path, filename))
                img.close()
            except IntegrityError:
                db.session.rollback()
                return "Duplicate image name {}".format(filename), 400
            return "OK", 200
        else:
            return "Invalid file", 400
    return render_template('assessments/panel/evidences.html', **context)


@blueprint.route('/<assessment_id>/evidences/<evidence_name>')
@limiter.exempt
@trusted_required
@assessment_allowed
def get_evidence(**kwargs):
    assessment = kwargs['assessment']

    image = Image.query.filter_by(
        assessment=assessment,
        name=kwargs['evidence_name']
    ).one()

    return send_from_directory(
        assessment.evidence_path(),
        image.name,
        mimetype='image/jpeg'
    )


@blueprint.route('/<assessment_id>/evidences/<evidence_name>/delete', methods=("POST",))
@auditor_required
@assessment_allowed
def delete_evidence(**kwargs):
    assessment = kwargs['assessment']

    if not current_user.audits(assessment):
        abort(403)

    image = Image.query.filter_by(
        assessment=assessment,
        name=kwargs['evidence_name']
    ).one()
    image_name = image.name
    image.delete()

    os.remove(os.path.join(assessment.evidence_path(), image_name))

    flash("Evidence deleted", "success")

    return redirect_back(".evidences", assessment_id=assessment.id)


@blueprint.route('/<assessment_id>/reports')
@trusted_required
@assessment_allowed
def reports(**kwargs):
    context = dict(
        assessment=kwargs['assessment']
    )
    return render_template('assessments/panel/reports.html', **context)


@blueprint.route('/<assessment_id>/reports/download', methods=('POST',))
@trusted_required
@assessment_allowed
def download_reports(**kwargs):
    assessment = kwargs['assessment']

    data = request.form.to_dict()
    data.pop('action', None)
    data.pop('csrf_token', None)

    templates = set(request.form.getlist('template_name'))
    templates = Template.query.filter(
        and_(
            Template.name.in_(templates),
            Template.clients.any(Client.id == assessment.client.id)
        )
    ).all()

    if not templates:
        flash('No report selected', 'danger')
        return redirect_back('.reports', assessment_id=assessment.id)

    report_path, report_file = generate_reports_bundle(assessment, templates)
    return send_from_directory(
        report_path,
        report_file,
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=report_file,
        add_etags=False,
        cache_timeout=0
    )


@blueprint.route('/<assessment_id>/reports/download/<template_name>', methods=('GET',))
@trusted_required
@assessment_allowed
def download_report(**kwargs):
    assessment = kwargs['assessment']

    template = Template.query.filter(
        Template.clients.any(Client.id == assessment.client.id)
    ).filter_by(
        name=kwargs['template_name']
    ).one()

    report_path, report_file = generate_reports_bundle(assessment, [template])
    return send_from_directory(
        report_path,
        report_file,
        mimetype='application/octet-stream',
        as_attachment=True,
        attachment_filename=report_file,
        add_etags=False,
        cache_timeout=0
    )
