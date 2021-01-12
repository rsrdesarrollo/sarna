from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import validators, SelectMultipleField, TextAreaField, StringField, FloatField, SelectField
from wtforms.validators import Optional

from sarna.auxiliary.upload_helpers import is_valid_evidence
from sarna.auxiliary.user_helpers import user_is_auditor
from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model import Assessment, Active, AffectedResource
from sarna.model.finding import Finding, FindingWebRequirement, \
    FindingMobileRequirement, FindingWebTest, FindingMobileTest, FindingCWE
from sarna.model.user import User
from sarna.model.enums import AssessmentType, AssessmentStatus, Language, ASVS, MASVS, WSTG, MSTG, CWE


class AssessmentForm(BaseEntityForm(Assessment,
                                    skip_attrs={'estimated_hours', 'effective_hours', 'end_date', 'platform'})):
    auditors = SelectMultipleField(
        coerce=User.coerce,
        validators=[Optional(), user_is_auditor]
    )
    bugtracking = StringField(label='Bug Tracking ticket #', render_kw={'placeholder': 'APPSECSER-XXX'})
    application = StringField(label='Application to assess', render_kw={'placeholder': 'APPWEB-MyApp'})
    riskprof_score = FloatField(label='Risk Profile Score', render_kw={'placeholder': '0.0'})
    status = SelectField(
        "Status",
        choices=AssessmentStatus.choices(),
        default=AssessmentStatus.Open,
        coerce=AssessmentStatus.coerce)
    type = SelectField(
        "Type",
        choices=AssessmentType.choices(),
        default=AssessmentType.Web,
        coerce=AssessmentType.coerce)
    lang = SelectField(
        "Language",
        choices=Language.choices(),
        default=Language.Spanish,
        coerce=Language.coerce)


class FindingEditForm(
    BaseEntityForm(
        Finding,
        skip_attrs={'name', 'client_finding_id'},
        hide_attrs={'cvss_v3_score', 'cvss_v3_vector'}
    ),
    BaseEntityForm(FindingWebRequirement, skip_pk=False),
    BaseEntityForm(FindingMobileRequirement, skip_pk=False),
    BaseEntityForm(FindingWebTest, skip_pk=False),
    BaseEntityForm(FindingMobileTest, skip_pk=False),
    BaseEntityForm(FindingCWE, skip_pk=False)
):
    affected_resources = TextAreaField(description='List of affected resources. One per line.',
                                       render_kw=dict(class_='noMD', rows=5))
    notes = TextAreaField(render_kw={'class_': 'noMD', 'placeholder': 'Optional notes.'})
    cwe_ref = SelectMultipleField(
        "Common Weakness Enumeration",
        choices=CWE.choices(),
        coerce=CWE.coerce,
        validators=[validators.DataRequired()])
    asvs_req = SelectMultipleField(
        label="ASVS - OWASP Application Security Verification Standard Requirement #",
        choices=ASVS.choices(),
        coerce=ASVS.coerce)
    masvs_req = SelectMultipleField(
        label="MASVS - OWASP Mobile Application Security Verification Standard Requirement #",
        choices=MASVS.choices(),
        coerce=MASVS.coerce)
    wstg_ref = SelectMultipleField(
        label="Web Security Testing Guide",
        choices=WSTG.choices(),
        coerce=WSTG.coerce)
    mstg_ref = SelectMultipleField(
        label="Mobile Security Testing Guide",
        choices=MSTG.choices(),
        coerce=MSTG.coerce)


class EvidenceCreateNewForm(FlaskForm):
    file = FileField(validators=[FileRequired(), is_valid_evidence])
