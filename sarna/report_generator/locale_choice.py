from sarna.model.enums.base_choice import BaseChoice
from sarna.model.enums.language import Language


def locale_choice(choice: BaseChoice, lang: Language):
    translation = getattr(choice, 'translation', None)
    if translation is None or lang not in translation or not translation[lang]:
        desc = getattr(choice, 'desc', None)
        if desc is not None:
            return desc
        else:
            return choice.name

    return translation[lang]
