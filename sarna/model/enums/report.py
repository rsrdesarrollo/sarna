from sarna.model.enums import Language
from sarna.model.enums.base_choice import BaseChoice


class SequenceName(BaseChoice):
    _init_ = "value translation"

    Image = 1, {
        Language.English: "Image",
        Language.Spanish: "Imagen"
    }
