from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SelectMultipleField, TextAreaField

from sarna.auxiliary.upload_helpers import is_valid_evidence
from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model import Assessment, Active, AffectedResource
from sarna.model.finding import Finding
from sarna.model.user import User


class AssessmentForm(BaseEntityForm(Assessment)):
    auditors = SelectMultipleField(
        coerce=User.coerce
    )


class FindingEditForm(BaseEntityForm(Finding, skip_attrs={'name', 'type', 'owasp_category'})):
    affected_resources = TextAreaField(description='List of affected resources. One per line.',
                                       render_kw=dict(class_='noMD', rows=5))


class ActiveCreateNewForm(
    BaseEntityForm(Active),
    BaseEntityForm(AffectedResource)
):
    pass


class EvidenceCreateNewForm(FlaskForm):
    file = FileField(validators=[FileRequired(), is_valid_evidence])
