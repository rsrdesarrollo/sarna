from sarna.model.enums.base_choice import BaseChoice


class AssessmentType(BaseChoice):
    Web = 1
    External_pentest = 2
    Internal_pentest = 7
    Mobile = 3
    iOS = 4
    Android = 5
    WiFi = 6


class AssessmentStatus(BaseChoice):
    Open = 1
    Closed = 2
    Archived = 3
