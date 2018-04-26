from pony.orm.dbapiprovider import IntConverter
from enum import Enum


class Choice(Enum):
    @classmethod
    def choices(cls):
        return tuple((elem, elem.name.replace("_", " ")) for elem in cls)

    @classmethod
    def coerce(cls, item):
        if item is None:
            return None

        return cls[item.replace(" ", "_")] if not isinstance(item, cls) else item

    def __str__(self):
        return self.name.replace("_", " ")

class Score(Choice):
    Info = 1
    Low = 2
    Medium = 3
    High = 4
    Critical = 5


class Language(Choice):
    Spanish = 1
    English = 2


class AssessmentType(Choice):
    Web = 1
    External_pentest = 2
    Mobile = 3
    iOS = 4
    Android = 5
    WiFi = 6


class FindingType(Choice):
    Web = 1
    OWASP = 2
    Infra = 3
    Config = 4


class FindingStatus(Choice):
    Pending = 1
    Reviewed = 2
    Confirmed = 3
    False_Positive = 4
    Other = 5


class AssessmentStatus(Choice):
    Open = 1
    Closed = 2
    Archived = 3


class ChoiceEnumConverter(IntConverter):
    def validate(self, val, obj=None):
        if not isinstance(val, Enum):
            raise ValueError('Must be an Enum.  Got {}'.format(type(val)))
        return val

    def sql2py(self, val):
        return self.py_type(val)

    def py2sql(self, val):
        return val.value
