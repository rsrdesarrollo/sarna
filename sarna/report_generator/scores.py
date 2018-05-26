from report_generator.style import RenderStyle
from sarna.model.aux import Score
from sarna.report_generator import *


def score_to_docx(score: Score, style: RenderStyle):
    ret = make_run(getattr(style, score.name.lower()), score.name)
    for warn in style._warnings:
        # TODO: something
        print(warn)

    return ret
