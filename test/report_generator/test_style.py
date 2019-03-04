from os import path

from sarna.report_generator.style import *
from test import TEST_PATH


def test_get_document_render_styles():
    styles = get_document_render_styles(
        path.join(
            TEST_PATH,
            'resources',
            'style_test.docx'
        )
    )

    default_style = styles.get_style()

    for attr in TABLE_STYLE_TAGS | PARAGRAPH_STYLE_TAGS | RAW_STYLE_TAGS:
        assert getattr(default_style, attr, None) is not None, "{} style not parsed correctly".format(attr)
