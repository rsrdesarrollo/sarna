from flask_wtf.file import FileField, FileRequired
from wtforms import SelectMultipleField

from sarna.auxiliary.upload_helpers import is_valid_template
from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.client import Client, Template
from sarna.model.user import User


class ClientForm(BaseEntityForm(Client)):
    managers = SelectMultipleField(
        coerce=User.coerce
    )
    auditors = SelectMultipleField(
        coerce=User.coerce
    )


class TemplateCreateNewForm(BaseEntityForm(Template, skip_pk=False)):
    file = FileField(validators=[FileRequired(), is_valid_template], description="Allowed templates: .docx")
