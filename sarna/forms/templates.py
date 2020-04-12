from flask_wtf.file import FileField, FileRequired

from sarna.auxiliary.upload_helpers import is_valid_template
from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model import Template


class TemplateCreateNewForm(BaseEntityForm(Template)):
    file = FileField(validators=[FileRequired(), is_valid_template], description="Allowed templates: .docx")