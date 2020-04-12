from flask_wtf import FlaskForm
from wtforms import SelectMultipleField, SelectField
from wtforms.validators import Optional

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
    templates = SelectMultipleField(
        coerce=Template.coerce,
        validators=[Optional()]
    )


class ClientChangeOwnerForm(FlaskForm):
    owner = SelectField(
        coerce=User.coerce,
        validators=[Optional(), users_are_managers]
    )
