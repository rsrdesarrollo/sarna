import re

__all__ = ['docx_escape', 'escape_url', 'list_level_style', 'make_run', 'make_paragraph']

def docx_escape(s, quote=False):
    """
    Replace special characters "&", "<" and ">" to HTML-safe sequences.
    If the optional flag quote is true (the default), the quotation mark
    characters, both double quote (") and single quote (') characters are also
    translated.
    """
    s = s.replace("&", "&amp;")  # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    if quote:
        s = s.replace('"', "&quot;")
        s = s.replace('\'', "’")
    return s


def escape_url(raw):
    """
    Escape urls to prevent code injection craziness. (Hopefully.)
    """
    from urllib.parse import quote
    return quote(raw, safe='/#:')


def make_run(rPr, text):
    return '<w:r>{}{}'.format(rPr, "<w:br/>".join(
        ('<w:t xml:space="preserve">{}</w:t></w:r>'.format(text) for text in docx_escape(text).split('\n'))
    ))


def list_level_style(pPr, level):
    return re.sub(
        '<\s*w:ilvl\s+w:val\s*=\s*"\d+"\s*/>',
        '<w:ilvl w:val="{}"/>'.format(level),
        pPr
    )


def make_paragraph(pPr, content, close_prev=False):
    if close_prev:
        return "</w:p><w:p>{}{}".format(pPr, content)
    else:
        return "<w:p>{}{}</w:p>".format(pPr, content)

