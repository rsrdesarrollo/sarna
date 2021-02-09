from sarna.model.enums import UserType
from flask_wtf import FlaskForm
from wtforms import SelectField, validators


class EditUserForm(FlaskForm):
    type = SelectField(
        label="User role",
        choices=UserType.none_blank_choices(),
        coerce=UserType.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
