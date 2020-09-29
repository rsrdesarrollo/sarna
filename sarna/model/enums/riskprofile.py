from sarna.model.enums.base_choice import BaseChoice


class RiskProfileType(BaseChoice):
    Low = 4
    Medium = 3
    High = 2
    Critical = 1
    Undefined = 5