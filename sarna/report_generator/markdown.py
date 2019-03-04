from typing import *

import mistletoe
from PIL import Image
from docx.section import Section
from docxtpl import DocxTemplate
from mistletoe.base_renderer import BaseRenderer

from sarna.report_generator import *
from sarna.report_generator.style import RenderStyle


def _get_img_prefered_size(img: AnyStr, section: Section):
    img: Image = Image.open(img)
    width, heigh = img.size
    max_width = (section.page_width.emu - section.left_margin.emu - section.right_margin.emu) * 0.8
    max_heigh = (section.page_height.emu / 2 - section.top_margin.emu - section.bottom_margin.emu) * 0.8
    if width > heigh:
        return max_width, None
    else:
        return None, max_heigh


class DOCXRenderer(BaseRenderer):
    """
    DOCX renderer class.

    See mistletoe.base_renderer module for more info.
    """

    def __call__(self, *args, **kwargs):
        self.warnings = set()
        return self

    def __init__(self, docx: DocxTemplate, img_path_trans: Callable):
        self.warnings = set()
        self.style = None
        self._tpl = docx
        self._img_path = img_path_trans
        self._suppress_ptag_stack = [False]
        self._suppress_rtag_stack = [False]
        self._list_style_stack = []
        self._mod_pstyle_stack = []
        self._list_level = -1
        super().__init__()

    def set_style(self, style: RenderStyle):
        self.style = style

    def render_strong(self, token):
        self._suppress_rtag_stack.append(True)
        render = make_run(self.style.strong, self.render_inner(token))
        self._suppress_rtag_stack.pop()
        return str(render)

    def render_emphasis(self, token):
        self._suppress_rtag_stack.append(True)
        render = make_run(self.style.italic, self.render_inner(token))
        self._suppress_rtag_stack.pop()
        return str(render)

    def render_inline_code(self, token):
        self.warnings.add('Marckdown inline code is not implemented. It will be ignored')
        return ''

    def render_strikethrough(self, token):
        self._suppress_rtag_stack.append(True)
        render = make_run(self.style.strike, self.render_inner(token))
        self._suppress_rtag_stack.pop()
        return str(render)

    def render_image(self, token):
        inner = self.render_inner(token)
        section = self._tpl.docx.sections[0]

        path = self._img_path(token.src)

        width, height = _get_img_prefered_size(path, section)
        pic = self._tpl.docx._part.new_pic_inline(
            path,
            width=width,
            height=height
        ).xml
        self._mod_pstyle_stack.append(self.style.image_caption)
        return '<w:r><w:drawing>{pic}</w:drawing></w:r><w:br/>{seq}{run}'.format(
            pic=pic,
            seq=make_sequence(),
            run=inner
        )

    def render_link(self, token):
        target = escape_url(token.target)

        self._suppress_rtag_stack.append(True)
        inner = self.render_inner(token)
        self._suppress_rtag_stack.pop()
        return make_run(self.style.href_caption, inner + " - ") + make_run(self.style.href_url, target)

    def render_raw_text(self, token):
        text = token.content.rstrip('\n').rstrip('\a')
        if self._suppress_rtag_stack[-1]:
            return text
        else:
            return make_run('', text)

    def render_heading(self, token):
        self.warnings.add('Markdown Headings are not implemented yet. It will be ignored')
        return ''

    def render_paragraph(self, token):
        inner = self.render_inner(token)

        try:
            style = self._mod_pstyle_stack.pop()
        except IndexError:
            style = self.style.paragraph

        if self._suppress_ptag_stack[-1]:
            return inner

        return make_paragraph(style, inner)

    def render_block_code(self, token):
        style = self.style.code
        return make_paragraph(style, self.render_inner(token))

    def render_list(self, token):
        if token.start:
            self._list_style_stack.append(self.style.ol)
        else:
            self._list_style_stack.append(self.style.ul)
        self._list_level += 1

        inner = self.render_inner(token)

        self._list_level -= 1
        self._list_style_stack.pop()
        return inner

    def render_list_item(self, token):
        style = self._list_style_stack[-1]
        self._suppress_ptag_stack.append(True)
        inner = self.render_inner(token)
        self._suppress_ptag_stack.pop()
        return make_paragraph(list_level_style(style, self._list_level), inner, self._list_level > 0)

    def render_escape_sequence(self, token):
        return self.render_inner(token)

    def render_line_break(self, token):
        # TODO: break raw in line
        return ''

    def render_thematic_break(self, token):
        self.warnings.add('Markdown ThematicBreak is not implemented. It will be ignored')
        return ''

    def render_quote(self, token):
        self.warnings.add('Markdown Quote is not implemented. It will be ignored')
        return ''

    def render_auto_link(self, token):
        self.warnings.add('Markdown AutoLink is not implemented. It will be ignored')
        return ''

    def render_table(self, token):
        header = self.render(token.header)
        content = self.render_inner(token)
        return make_table(self.style.table, header, content)

    def render_table_row(self, token, is_header=False):
        content = self.render_inner(token)
        return make_table_row(content)

    def render_table_cell(self, token, in_header=False):
        content = self.render_inner(token)
        return make_table_cell(self.style.paragraph, content)

    @staticmethod
    def render_separator(token):
        return '<w:p></w:p>'

    def render_document(self, token):
        self.footnotes.update(token.footnotes)
        ret = self.render_inner(token)
        self.warnings = self.warnings | self.style._warnings

        return ret


def markdown_to_docx(markdown, render: DOCXRenderer):
    ret = mistletoe.markdown(markdown + "\r\n", render)
    for warn in render.warnings:
        # TODO: something
        print(warn)

    return ret
