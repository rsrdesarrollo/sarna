from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SelectMultipleField, SelectField
from wtforms.validators import Optional

from sarna.auxiliary.upload_helpers import is_valid_template
from sarna.auxiliary.user_helpers import users_are_managers, user_is_auditor
from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.client import Client, Template
from sarna.model.user import User


class ClientForm(BaseEntityForm(Client)):
    managers = SelectMultipleField(
        coerce=User.coerce,
        validators=[Optional(), users_are_managers]
    )
    auditors = SelectMultipleField(
        coerce=User.coerce,
        validators=[Optional(), user_is_auditor]
    )


class ClientChangeOwnerForm(FlaskForm):
    owner = SelectField(
        coerce=User.coerce,
        validators=[Optional(), users_are_managers]
    )


class TemplateCreateNewForm(BaseEntityForm(Template, skip_pk=False)):
    file = FileField(validators=[FileRequired(), is_valid_template], description="Allowed templates: .docx")
