import magic
import re
from sarna import config
from wtforms.validators import ValidationError


def _get_mime_ext(file):
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)

    ext = file.filename.split('.')[-1].lower()
    return mime, ext


def is_valid_evidence(form, field):
    mime, ext = _get_mime_ext(field.data)
    if not re.match(config.EVIDENCES_ALLOW_MIME, mime) or ext not in config.EVIDENCES_ALLOW_EXTENSIONS:
        raise ValidationError('Invalid file')


def is_valid_template(form, field):
    mime, ext = _get_mime_ext(field.data)
    if not re.match(config.TEMPLATES_ALLOW_MIME, mime) or ext not in config.TEMPLATES_ALLOW_EXTENSIONS:
        raise ValidationError('Invalid file')
