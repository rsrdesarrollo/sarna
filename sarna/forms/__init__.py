import datetime

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from pony.orm.core import Entity, Attribute
from wtforms import validators
from wtforms.fields import BooleanField, SelectField, StringField, TextAreaField
from wtforms.fields.html5 import IntegerField, DateField

from sarna.aux.upload_helpers import *
from sarna.model import *

simple_str_validator = validators.Regexp('^[\w\d \t_\[\]\(\)<>"\'.*:|$!-]+$')


class EntityForm(type):
    def __new__(cls, entity: Entity, skip_attrs={}, custom_validators=dict(), skip_pk=True):
        class Form(FlaskForm):
            pass

        for k, _ in entity._adict_.items():
            if k in skip_attrs:
                continue

            field: Attribute = getattr(entity, k)
            if skip_pk and field.is_pk:
                continue

            if field.is_basic and not field.is_discriminator:
                vals = []
                required = isinstance(field, Required)

                if k in custom_validators:
                    vals.extend(custom_validators[k])

                if required:
                    vals.append(validators.DataRequired())

                if field.is_pk and field.py_type == str:
                    # Just use things that wont mess the uri: Issue: pallets/flask#900
                    vals.append(simple_str_validator)

                t = None
                if field.py_type == str:
                    t = StringField(validators=vals)
                elif issubclass(field.py_type, Choice):
                    label = k[0].upper() + k[1:]
                    t = SelectField(
                        " ".join(label.split('_')),
                        validators=vals,
                        choices=field.py_type.choices(),
                        coerce=field.py_type.coerce
                    )
                elif field.py_type == LongStr:
                    t = TextAreaField(validators=vals)
                elif field.py_type == bool:
                    t = BooleanField(validators=vals)
                elif field.py_type == int:
                    t = IntegerField(validators=vals if required else [validators.Optional()])
                elif field.py_type == datetime.date:
                    t = DateField(validators=vals if required else [validators.Optional()])

                if t is not None:
                    setattr(Form, k, t)

        return Form


class BulkActionForm(FlaskForm):
    action = StringField()


"""
CLIENTS
"""


class ClientForm(EntityForm(Client)):
    pass


"""
ASSESSMENTS
"""


class AssessmentForm(EntityForm(Assessment)):
    pass


"""
FINDING DATABASE
"""


class FindingTemplateCreateNewForm(EntityForm(FindingTemplate), EntityForm(FindingTemplateTranslation)):
    pass


class FindingTemplateEditForm(EntityForm(FindingTemplate)):
    pass


class FindingTemplateAddTranslationForm(EntityForm(FindingTemplateTranslation)):
    pass


class FindingTemplateEditTranslationForm(EntityForm(FindingTemplateTranslation, skip_attrs={'lang'})):
    pass


class FindingTemplateAddSolutionForm(EntityForm(
    Solution,
    custom_validators=dict(
        name=[validators.Regexp('[\w_-]+')]
    )
)):
    pass


class FindingTemplateEditSolutionForm(EntityForm(
    Solution,
    skip_attrs={'lang', 'name'},
    custom_validators=dict(
        name=[validators.Regexp('[\w_-]+')]
    )
)):
    pass


"""
FINDINGS
"""


class FindingEditForm(EntityForm(Finding, skip_attrs={'name', 'type', 'owasp_category'})):
    affected_resources = TextAreaField(description='List of affected resources. One per line.',
                                       render_kw=dict(class_='noMD', rows=5))


"""
ACTIVES
"""


class ActiveCreateNewForm(
    EntityForm(Active, skip_pk=False),
    EntityForm(AffectedResource)
):
    pass


class ActiveCreateBulkForm(FlaskForm):
    TextAreaField(validators=[validators.DataRequired()], description="List of actives. One per line.")


"""
TEMPLATES
"""


class TemplateCreateNewForm(
    EntityForm(Template)
):
    file = FileField(validators=[FileRequired(), is_valid_template], description="Allowed templates: .docx")


TemplateCreateNewForm.name.kwargs['validators'].append(simple_str_validator)

"""
EVIDENCE
"""


class EvidenceCreateNewForm(FlaskForm):
    file = FileField(validators=[FileRequired(), is_valid_evidence])
