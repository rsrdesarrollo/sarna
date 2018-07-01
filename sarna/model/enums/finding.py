from sarna.model.enums.base_choice import BaseChoice


class FindingType(BaseChoice):
    Web = 1
    Infra = 2
    Mobile = 3
    WiFi = 4


class FindingStatus(BaseChoice):
    Pending = 1
    Reviewed = 2
    Confirmed = 3
    False_Positive = 4
    Other = 5
