from datetime import datetime, date
from pony.orm import *
from .aux import Language, AssessmentStatus, AssessmentType, FindingStatus, FindingType
from .aux import ChoiceStrConverter

db = Database()


class Client(db.Entity):
    id = PrimaryKey(int, auto=True)
    assessments = Set('Assessment')
    templates = Set('Template')
    short_name = Required(str, 64)
    long_name = Required(str, 128)
    users = Set('User')


class Assessment(db.Entity):
    id = PrimaryKey(int, auto=True)
    name = Required(str, 32)
    reports = Set('Report')
    lang = Required(Language, 3)
    type = Required(AssessmentType, 3)
    platform = Required(str, 64)
    status = Required(AssessmentStatus, 3)
    client = Required(Client)
    actives = Set('Active')
    findings = Set('Finding')
    images = Set('Image')
    approvals = Set('Approval')
    creation_date = Required(datetime, default=lambda: datetime.now())
    users = Set('User')
    start_date = Optional(date)
    end_date = Optional(date)
    estimated_hours = Optional(int)
    effective_hours = Optional(int)


class Report(db.Entity):
    id = PrimaryKey(int, auto=True)
    assessment = Required(Assessment)
    name = Required(str, 64)
    template = Required('Template')


class FindingTemplate(db.Entity):
    id = PrimaryKey(int, auto=True)
    langs = Required(Json)  # list of langs
    title = Required(Json)  # locale text
    type = Required(FindingType, 3)
    definition = Required(Json)  # locale text
    solutions = Set('Solution')
    references = Required(Json)  # locale text
    tech_risk = Required(int, min=0, max=4)  # [0 to 4]
    dissemination = Required(int, min=0, max=4)  # [0 to 4]
    solution_complexity = Required(int, min=0, max=4)  # [0 to 4]


class Finding(FindingTemplate):
    affected_resources = Set('AffectedResource')
    status = Required(FindingStatus, 3)
    assessment = Required(Assessment)
    description = Optional(Json, lazy=True)  # locale text
    business_risk = Optional(int, min=0, max=4)  # [0 to 4]
    exploitability = Optional(int, min=0, max=4)  # [0 to 4]
    cvss_v3_vector = Optional(str, 124)
    cvss_score = Optional(float)


class Active(db.Entity):
    id = PrimaryKey(int, auto=True)
    affected_resources = Set('AffectedResource')
    assessment = Required(Assessment)
    name = Required(str)


class AffectedResource(db.Entity):
    id = PrimaryKey(int, auto=True)
    active = Required(Active)
    route = Optional(str)
    findings = Set(Finding)


class Template(db.Entity):
    name = PrimaryKey(str, 32)
    reports = Set(Report)
    description = Optional(str, 128)
    clients = Set(Client)
    type = Required(str, 5)  # Choice


class Solution(db.Entity):
    id = PrimaryKey(int, auto=True)
    context = Optional(str, 32, default='generic')
    text = Optional(Json)  # locale text
    finding_template = Required(FindingTemplate)


class Image(db.Entity):
    id = PrimaryKey(int, auto=True)
    name = Required(str)
    assessment = Required(Assessment)
    label = Optional(Json)  # locale text


class Approval(db.Entity):
    id = PrimaryKey(int, auto=True)
    date = Required(datetime, default=lambda: datetime.now())
    assessment = Required(Assessment)
    user = Required('User')


class User(db.Entity):
    id = PrimaryKey(int, auto=True)
    is_admin = Required(bool, default=False)
    assessments = Set(Assessment)
    clients = Set(Client)
    approvals = Set(Approval)


def init_database():
    db.bind(provider='sqlite', filename='/tmp/database.sqlite', create_db=True)

    for cls in (Language, AssessmentStatus, AssessmentType, FindingStatus, FindingType):
        db.provider.converter_classes.append((cls, ChoiceStrConverter(cls)))

    db.generate_mapping(create_tables=True)


if __name__ == '__main__':
    init_database()
