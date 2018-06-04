import re
from typing import AnyStr, Set, Dict

from docx import Document
from docx.document import Document as DocType
from jinja2.exceptions import TemplateSyntaxError

_BEGIN_STYLE = re.compile('##\s*begin\s*style\s*(\w+)\s*##', re.IGNORECASE)
_END_STYLE = re.compile('##\s*end\s*style\s*##', re.IGNORECASE)
_TAG_STYLE = re.compile('##\s*(\w+)\s*##', re.IGNORECASE)

PSTYLE_TAGS = {'ul', 'ol', 'paragraph', 'code', 'image_caption'}
RSTYLE_TAGS = {
    'href_caption', 'href_url', 'na', 'info', 'low', 'medium', 'high', 'critical',
    'strong', 'italic', 'strike'
}


class RenderStyle:
    name: AnyStr
    _warnings: Set

    ul: AnyStr
    ol: AnyStr
    paragraph: AnyStr
    code: AnyStr
    href_caption: AnyStr
    href_url: AnyStr
    image_caption: AnyStr

    na: AnyStr
    info: AnyStr
    low: AnyStr
    medium: AnyStr
    high: AnyStr
    critical: AnyStr
    strong: AnyStr
    italic: AnyStr
    strike: AnyStr

    _data = dict(
        ul=None,
        ol=None,
        paragraph=None,
        code=None,
        href_caption=None,
        href_url=None,
        image_caption=None,
        na=None,
        info=None,
        low=None,
        medium=None,
        high=None,
        critical=None,
        strong=None,
        italic=None,
        strike=None
    )

    def __init__(self, **kwargs):
        if 'name' not in kwargs:
            raise ValueError('Attribute name is required for a RenderStyle')

        self.name = kwargs.pop('name')
        self._warnings = set()

        for k, v in kwargs.items():
            if k in self._data and not k.startswith('_'):
                self._data[k] = v
            else:
                self._warnings.add(
                    'Invalid style descriptor {} on style name {}'.format(k, self.name)
                )

    def __getattr__(self, item):
        attr = self._data.get(item, None)
        if attr is None:
            self._warnings.add(
                "Try to use {} on style {} but is not defined".format(item, self.name)
            )
        return attr


class RenderStylesCollection:
    _styles: Dict[AnyStr, RenderStyle]

    def __init__(self):
        self._styles = dict()

    def add_style(self, style: RenderStyle):
        if style.name in self._styles:
            raise ValueError('Style {} already defined'.format(style.name))
        self._styles[style.name] = style
        return self

    def get_style(self, name='default'):
        if name not in self._styles:
            raise ValueError('Style {} not defined'.format(name))
        return self._styles[name]


def get_document_render_styles(doc_path) -> RenderStylesCollection:
    styles = RenderStylesCollection()

    doc: DocType = Document(doc_path)

    style_name = None
    attrs = dict()
    for paragraph in doc.paragraphs:
        text = paragraph.text
        if not style_name:
            match = _BEGIN_STYLE.match(text)
            if match:
                style_name = match.group(1)
        else:
            if _END_STYLE.match(text):
                styles.add_style(RenderStyle(name=style_name, **attrs))
                style_name = None
                attrs = dict()
                continue

            match = _TAG_STYLE.match(text)
            if match:
                tag_name = match.group(1).lower()
                if tag_name in PSTYLE_TAGS:
                    # Get style from paragraph
                    if paragraph._element.pPr is not None:
                        attrs[tag_name] = paragraph._element.pPr.xml
                    else:
                        attrs[tag_name] = '<w:pPr></w:pPr>'
                elif tag_name in RSTYLE_TAGS:
                    # Get style from Run
                    if paragraph.runs[0]._element.rPr is not None:
                        attrs[tag_name] = paragraph.runs[0]._element.rPr.xml
                    else:
                        attrs[tag_name] = '<w:rPr></w:rPr>'

    if style_name is not None:
        raise TemplateSyntaxError(
            'Unexpected end of template style definition {}. Never closed'.format(style_name),
            None
        )

    return styles
