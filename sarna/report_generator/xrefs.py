from markupsafe import Markup

from sarna.report_generator import make_run

_xrefs_runs = """
<w:r>
    <w:rPr></w:rPr>
    <w:fldChar w:fldCharType="begin"></w:fldChar>
</w:r>
<w:r>
    <w:rPr></w:rPr>
    <w:instrText> REF {ref} {ops} </w:instrText>
</w:r>
<w:r>
    <w:fldChar w:fldCharType="separate"/>
</w:r>
<w:r>
    <w:rPr></w:rPr>
    <w:t>[ref]</w:t>
</w:r>
<w:r>
    <w:fldChar w:fldCharType="end"/>
</w:r>
"""

_bookmark = """
<w:bookmarkStart w:id="{ref}" w:name="{ref}"/>
{run}
<w:bookmarkEnd w:id="{ref}"/>
"""


def _ref_name(elem):
    return "_Ref{:09d}".format(elem.id)


def xref(elem, xref_type='number'):
    ref_name = _ref_name(elem)
    ref_ops = ""
    if xref_type == 'number':
        ref_ops = "\\r \\h"
    elif xref_type == 'title':
        ref_ops = "\\h"

    return Markup(_xrefs_runs.format(ref=ref_name, ops=ref_ops))


def bookmark(elem, attr):
    run = make_run('', getattr(elem, attr))
    return Markup(_bookmark.format(ref=_ref_name(elem), run=run))


__all__ = ['xref', 'bookmark']
