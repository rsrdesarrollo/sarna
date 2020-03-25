from flask_sqlalchemy import DefaultMeta as Entity
from flask_wtf import FlaskForm
from sqlalchemy import String, Boolean, Integer, Date
from wtforms import validators, SelectField, BooleanField, StringField, TextAreaField
from wtforms.fields.html5 import IntegerField, DateField

from sarna.model.sql_types.enum import Enum

simple_str_validator = validators.Regexp('^[\w\d \t_\[\]\(\)<>"\'.*:|$!-]+$')


class BaseEntityForm(type):
    def __new__(mcs, entity: Entity, skip_attrs=None, custom_validators=None, skip_pk=True, hide_attrs=None):
        if skip_attrs is None:
            skip_attrs = set()
        if custom_validators is None:
            custom_validators = dict()
        if hide_attrs is None:
            hide_attrs = set()

        class Form(FlaskForm):
            pass

        for colum in entity.__table__.columns:
            if colum.name in skip_attrs:
                continue

            if skip_pk and colum.primary_key:
                continue

            if colum.name in hide_attrs:
                kwargs = dict(label='', render_kw=dict(style="display:none;"))
            else:
                kwargs = dict(render_kw=dict())

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
                        coerce=colum.type.enum_class.coerce,
                        **kwargs
                    )
                elif isinstance(colum.type, Boolean):
                    t = BooleanField(validators=vals, **kwargs)
                elif isinstance(colum.type, Integer):
                    t = IntegerField(validators=vals if required else [validators.Optional()], **kwargs)
                elif isinstance(colum.type, Date):
                    t = DateField(validators=vals if required else [validators.Optional()], **kwargs)
                elif isinstance(colum.type, String) and colum.type.length:
                    kwargs["render_kw"]["maxlength"] = colum.type.length
                    t = StringField(validators=vals, **kwargs)
                elif isinstance(colum.type, String):
                    t = TextAreaField(validators=vals, **kwargs)

                if t is not None:
                    setattr(Form, colum.name, t)

        return Form
