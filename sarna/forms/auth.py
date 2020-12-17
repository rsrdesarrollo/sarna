from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, validators, BooleanField

from sarna.model.enums import UserType


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


class AddUserForm(FlaskForm):
    username = StringField(validators=[validators.DataRequired()])
    #password = StringField(validators=[validators.DataRequired()])
    #passwordrep = StringField(validators=[validators.DataRequired()])
    #isadmin = BooleanField()    
    type = SelectField(
        label="User role",
        choices=UserType.choices(),
        coerce=UserType.coerce)
