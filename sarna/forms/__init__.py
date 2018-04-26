from flask_wtf import FlaskForm
from wtforms.fields import StringField, SelectField, IntegerField
from wtforms.validators import DataRequired
from pony.orm.core import Entity, Attribute, Required

from sarna.model.aux import Choice
from sarna.model import Client, Assessment


class EntityForm(type):
    def __new__(cls, entity: Entity):
        class Form(FlaskForm):
            pass

        for k, _ in entity._adict_.items():
            field: Attribute = getattr(entity, k)
            if field.is_basic and not field.is_pk:
                validators = []
                if isinstance(field, Required):
                    validators.append(DataRequired())

                t = None
                if field.py_type == str:
                    t = StringField(validators=validators)
                elif issubclass(field.py_type, Choice):
                    label = k[0].upper() + k[1:]
                    t = SelectField(
                        " ".join(label.split('_')),
                        validators=validators,
                        choices=field.py_type.choices(),
                        coerce=field.py_type.coerce
                    )
                if t is not None:
                    setattr(Form, k, t)

        return Form


class ClientForm(EntityForm(Client)):
    pass


class AssessmentForm(EntityForm(Assessment)):
    pass
