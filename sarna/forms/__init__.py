from flask_sqlalchemy.model import DefaultMeta as Entity
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from sqlalchemy.sql.sqltypes import Integer, String, Boolean, Date
from wtforms import validators
from wtforms.fields import BooleanField, SelectField, StringField, TextAreaField
from wtforms.fields.html5 import IntegerField, DateField

from sarna.auxiliary.upload_helpers import *
from sarna.model import *
from sarna.model.sql_types.enum import Enum

simple_str_validator = validators.Regexp('^[\w\d \t_\[\]\(\)<>"\'.*:|$!-]+$')

__all__ = [
    'ClientForm', 'AssessmentForm', 'FindingTemplateEditForm', 'FindingTemplateCreateNewForm',
    'FindingTemplateEditSolutionForm', 'FindingEditForm', 'FindingTemplateAddSolutionForm',
    'FindingTemplateAddTranslationForm', 'FindingTemplateEditTranslationForm', 'ActiveCreateNewForm',
    'TemplateCreateNewForm', 'EvidenceCreateNewForm', 'OtpConfirmForm', 'ChangePasswordForm', 'AddUserForm'
]


def props(cls):
    return (i for i in cls.__dict__.keys() if not i.startswith('_'))


class EntityForm(type):
    def __new__(mcs, entity: Entity, skip_attrs=None, custom_validators=None, skip_pk=True):
        if skip_attrs is None:
            skip_attrs = {}
        if custom_validators is None:
            custom_validators = dict()

        class Form(FlaskForm):
            pass

        for colum in entity.__table__.columns:
            if colum.name in skip_attrs:
                continue

            if skip_pk and colum.primary_key:
                continue

            if not colum.foreign_keys:
                vals = []
                required = not colum.nullable

                if colum.name in custom_validators:
                    vals.extend(custom_validators[colum.name])

                if required:
                    vals.append(validators.DataRequired())

                if colum.primary_key and type(colum.type) == String:
                    # Just use things that wont mess the uri: Issue: pallets/flask#900
                    vals.append(simple_str_validator)

                t = None

                if isinstance(colum.type, Enum):
                    label = colum.name[0].upper() + colum.name[1:]
                    t = SelectField(
                        " ".join(label.split('_')),
                        validators=vals,
                        choices=colum.type.enum_class.choices(),
                        coerce=colum.type.enum_class.coerce
                    )
                elif isinstance(colum.type, Boolean):
                    t = BooleanField(validators=vals)
                elif isinstance(colum.type, Integer):
                    t = IntegerField(validators=vals if required else [validators.Optional()])
                elif isinstance(colum.type, Date):
                    t = DateField(validators=vals if required else [validators.Optional()])
                elif isinstance(colum.type, String) and colum.type.length:
                    t = StringField(validators=vals, render_kw=dict(maxlength=colum.type.length))
                elif isinstance(colum.type, String):
                    t = TextAreaField(validators=vals)

                if t is not None:
                    setattr(Form, colum.name, t)

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


class FindingTemplateCreateNewForm(
    EntityForm(FindingTemplate),
    EntityForm(FindingTemplateTranslation, skip_pk=False)
):
    pass


class FindingTemplateEditForm(EntityForm(FindingTemplate)):
    pass


class FindingTemplateAddTranslationForm(EntityForm(
    FindingTemplateTranslation,
    skip_pk=False
)):
    pass


class FindingTemplateEditTranslationForm(EntityForm(FindingTemplateTranslation, skip_attrs={'lang'})):
    pass


class FindingTemplateAddSolutionForm(EntityForm(
    Solution,
    skip_pk=False,
    custom_validators=dict(
        name=[validators.Regexp('[\w_-]+')]
    )
)):
    pass


class FindingTemplateEditSolutionForm(EntityForm(
    Solution,
    skip_attrs={'lang'},
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
    EntityForm(Active),
    EntityForm(AffectedResource)
):
    pass


"""
TEMPLATES
"""


class TemplateCreateNewForm(
    EntityForm(Template, skip_pk=False)
):
    file = FileField(validators=[FileRequired(), is_valid_template], description="Allowed templates: .docx")


TemplateCreateNewForm.name.kwargs['validators'].append(simple_str_validator)

"""
EVIDENCE
"""


class EvidenceCreateNewForm(FlaskForm):
    file = FileField(validators=[FileRequired(), is_valid_evidence])


"""
Login form
"""


class LoginForm(FlaskForm):
    username = StringField(validators=[validators.DataRequired()])
    password = StringField(validators=[validators.DataRequired()])
    otp = StringField(label='Google Authenticator')


class OtpConfirmForm(FlaskForm):
    otp = StringField(validators=[validators.DataRequired()], label='Google Authenticator')
    password = StringField(validators=[validators.DataRequired()])


class ChangePasswordForm(FlaskForm):
    oldpassword = StringField(validators=[validators.DataRequired()], label='Old Password')
    newpassword = StringField(validators=[validators.DataRequired()], label='New Password')
    newpasswordrep = StringField(validators=[validators.DataRequired()], label='Repeat new Password')
    otp = StringField(label='Google Authenticator')


"""
User managment Forms
"""


class AddUserForm(FlaskForm):
    username = StringField(validators=[validators.DataRequired()])
    password = StringField(validators=[validators.DataRequired()])
    passwordrep = StringField(validators=[validators.DataRequired()])
    isadmin = BooleanField()
