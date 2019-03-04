from sarna.report_generator.markdown import *

SAMPLE_TABLE_01 = \
"""|    Col1   |   Col2  |            Col3            |
|:------------:|:-------:|:--------------------------:|
| Cell1.1      | Cell1.2 | Cell1.3                    |
| dsadas       | adssad  | dsaasdasd __italic__       |
| asddsaasd    | sa d    |  adsasd das asd **strong** |
"""

def test_table_generation():
    from xml.etree import ElementTree
    style = RenderStyle(
        name="default",
        paragraph="<w:pPr></w:pPr>", table="<w:tblPr></w:tblPr>", strong="<w:rPr></w:rPr>", italic="<w:rPr></w:rPr>"
    )
    renderer = DOCXRenderer(None, None)
    renderer.set_style(style)
    data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
    {}
    </w:body>
    </w:document>
    """.format(markdown_to_docx(SAMPLE_TABLE_01, renderer))

    valid_xml = ElementTree.fromstring(data)

    assert valid_xml
