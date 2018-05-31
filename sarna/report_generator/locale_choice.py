from sarna.model import Language
from sarna.model.auxiliary import Choice


def locale_choice(choice: Choice, lang: Language):
    translation = getattr(choice, 'translation', None)
    if translation is None or lang not in translation or not translation[lang]:
        desc = getattr(choice, 'desc', None)
        if desc is not None:
            return desc
        else:
            return choice.name

    return translation[lang]
