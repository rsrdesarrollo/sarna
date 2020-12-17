from sarna.model.user import User
from sarna.model.enums import UserType
from flask_wtf import FlaskForm
from wtforms import SelectField


class EditUserForm(FlaskForm):
    type = SelectField(
        label="User role",
        choices=UserType.choices(),
        coerce=UserType.coerce)