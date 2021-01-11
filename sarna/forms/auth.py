from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, validators

from sarna.model.enums import UserType


class LoginForm(FlaskForm):
    username = StringField(validators=[validators.DataRequired(), validators.Length(max=128)])
    password = StringField(validators=[validators.DataRequired()])
    otp = StringField(label='Google Authenticator')


class AddUserForm(FlaskForm):
    username = StringField(validators=[validators.DataRequired(), validators.Length(max=128)])
    type = SelectField(
        label="User role",
        choices=UserType.choices(),
        coerce=UserType.coerce)
