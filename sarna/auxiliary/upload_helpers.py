import re

import magic
from wtforms.validators import ValidationError

from sarna.core.config import config

__all__ = ['is_valid_evidence', 'is_valid_template']


def _get_mime_ext(file):
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)

    ext = file.filename.split('.')[-1].lower()
    return mime, ext


def is_valid_evidence(_, field):
    mime, ext = _get_mime_ext(field.data)
    if not re.match(config.EVIDENCES_ALLOW_MIME, mime) or ext not in config.EVIDENCES_ALLOW_EXTENSIONS:
        raise ValidationError('Invalid file')


def is_valid_template(_, field):
    if field.data is None:
        return

    mime, ext = _get_mime_ext(field.data)
    if not re.match(config.TEMPLATES_ALLOW_MIME, mime) or ext not in config.TEMPLATES_ALLOW_EXTENSIONS:
        raise ValidationError('Invalid file')
