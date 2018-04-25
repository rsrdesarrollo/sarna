from pony.orm.dbapiprovider import StrConverter
import inspect

Scores = ['Info', 'Low', 'Medium', 'High', 'Critical']


class Choice:
    @classmethod
    def _members(cls):

        return (
            sorted((
                item for item in inspect.getmembers(
                    cls,
                    lambda x: not inspect.isroutine(x)
                ) if not item[0].startswith('_')),
                key=lambda x: x[1][1]
            )
        )

    @classmethod
    def to_tuple(cls):
        ret = tuple((pair[0],pair[1][0]) for pair in cls._members() if not pair[0].startswith('_'))
        return ret

    @classmethod
    def keys(cls):
        yield from (pair[0] for pair in cls._members() if not pair[0].startswith('_'))

    @classmethod
    def values(cls):
        yield from (pair[1][0] for pair in cls._members() if not pair[0].startswith('_'))


class Language(Choice):
    esp = ("Spanish", 0)
    eng = ("English", 1)


class AssessmentType(Choice):
    web = ("Web", 0)
    ext = ("External", 1)
    mob = ("Mobile", 1)
    ios = ("iOS", 1)
    apk = ("Android", 1)
    wif = ("WiFi", 1)


class FindingType(Choice):
    web = ("Web", 1)
    owa = ("OWASP", 1)
    inf = ("Infra", 1)
    cfg = ("Config", 1)


class FindingStatus(Choice):
    pen = ("Pending", 0)
    rev = ("Reviewed", 1)
    con = ("Confirmed", 2)
    fpo = ("False Positive", 3)
    oth = ("Other", 9)


class AssessmentStatus(Choice):
    opn = ("Open", 0)
    clo = ("Closed", 1)
    arc = ("Archived", 2)


class ChoiceStrConverter(type):
    def __new__(cls, choice: Choice):
        class _ChoiceStrConverter(StrConverter):
            def validate(self, val, obj=None):
                if val not in choice.keys():
                    raise ValueError('Value not in: {}'.format(",".join(choice.keys())))
                return val

        return _ChoiceStrConverter
