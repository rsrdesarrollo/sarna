from sarna.model.enums import Language
from sarna.model.enums.base_choice import BaseChoice


class Score(BaseChoice):
    _init_ = "value translation"
    Info = 1, {
        Language.English: 'Info',
        Language.Spanish: 'Informativo'
    }
    Low = 2, {
        Language.English: 'Low',
        Language.Spanish: 'Bajo'
    }
    Medium = 3, {
        Language.English: 'Medium',
        Language.Spanish: 'Medio'
    }
    High = 4, {
        Language.English: 'High',
        Language.Spanish: 'Alto'
    }
    Critical = 5, {
        Language.English: 'Critical',
        Language.Spanish: 'Crítico'
    }
    NA = 6, {
        Language.English: 'N/A',
        Language.Spanish: 'N/A'
    }
