from sarna.report_generator.style import RenderStyle
from sarna.model.enumerations import Score, Language
from sarna.report_generator.locale_choice import locale_choice
from sarna.report_generator import make_run


def score_to_docx(score: Score, style: RenderStyle, lang: Language):
    ret = make_run(getattr(style, score.name.lower()), locale_choice(score, lang))
    for warn in style._warnings:
        # TODO: something
        print(warn)

    return ret
