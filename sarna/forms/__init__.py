from flask_wtf import FlaskForm
from wtforms.fields import StringField, SelectField, IntegerField
from wtforms.validators import DataRequired


class ClientForm(FlaskForm):
    short_name = StringField(validators=[DataRequired()])
    long_name = StringField(validators=[DataRequired()])


# TODO: Externalise constants choices.
class AssessmentForm(FlaskForm):
    lang = SelectField("Language", validators=[DataRequired()], choices=(('en', 'English'), ('es', 'Spanish')))
    type = SelectField("Type", validators=[DataRequired()], choices=(('web', 'Web'), ('ext', 'External')))
    platform = StringField(validators=[DataRequired()])
