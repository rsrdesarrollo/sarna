from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SelectMultipleField, TextAreaField, StringField
from wtforms.validators import Optional

from sarna.auxiliary.upload_helpers import is_valid_evidence
from sarna.auxiliary.user_helpers import user_is_auditor
from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model import Assessment, Active, AffectedResource
from sarna.model.finding import Finding
from sarna.model.user import User


class AssessmentForm(BaseEntityForm(Assessment, skip_attrs={'estimated_hours', 'effective_hours', 'end_date', 'platform'})):
    auditors = SelectMultipleField(
        coerce=User.coerce,
        validators=[Optional(), user_is_auditor]
    )
    bugtracking = StringField(label='Bug Tracking ticket #', render_kw={'placeholder': 'APPSECSER-XXX'})
    application = StringField(label='Application to assess', render_kw={'placeholder': 'APPWEB-MyApp'})


class FindingEditForm(BaseEntityForm(Finding, skip_attrs={'name', 'client_finding_id', 'tech_risk', 'business_risk', 'exploitability', 'dissemination', 'solution_complexity'},
                                     hide_attrs={'cvss_v3_score', 'cvss_v3_vector'})):
    affected_resources = TextAreaField(description='List of affected resources. One per line.',
                                       render_kw=dict(class_='noMD', rows=5))
    notes = TextAreaField(render_kw={'class_': 'noMD', 'placeholder': 'Optional notes.'})


class ActiveCreateNewForm(
    BaseEntityForm(Active),
    BaseEntityForm(AffectedResource)
):
    pass


class EvidenceCreateNewForm(FlaskForm):
    file = FileField(validators=[FileRequired(), is_valid_evidence])
