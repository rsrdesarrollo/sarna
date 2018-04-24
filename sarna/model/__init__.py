from datetime import datetime
from pony.orm import *

db = Database()


class Client(db.Entity):
    id = PrimaryKey(int, auto=True)
    assessments = Set('Assessment')
    templates = Set('Template')
    short_name = Required(str, 64)
    long_name = Optional(str, 128)


class Assessment(db.Entity):
    id = PrimaryKey(int, auto=True)
    lang = Required(str, 2)
    type = Required(str)  # Choice from: Web, External, WiFi, Android, iOS, Mobile
    platform = Required(str)
    client = Required(Client)
    actives = Set('Active')
    findings = Set('Finding')
    reports = Set('Report')
    images = Set('Image')
    creation_date = Required(datetime, default=lambda: datetime.now())
    is_open = Required(bool, default=True)
    approvals = Set('Approval')


class Report(db.Entity):
    id = PrimaryKey(int, auto=True)
    assessment = Required(Assessment)
    name = Required(str, 64)
    template = Required('Template')


class FindingTemplate(db.Entity):
    id = PrimaryKey(int, auto=True)
    lang = Required(str, 2)
    title = Required(str, 64)
    definition = Required(LongStr)
    solutions = Set('Solution')
    references = Required(LongStr)
    tech_risk = Required(int)
    dissemination = Required(int)
    solution_complexity = Required(int)


class Finding(FindingTemplate):
    assessment = Required(Assessment)
    description = Optional(LongStr, lazy=True)
    business_risk = Optional(int)
    exploitability = Optional(int)
    cvss_v3_vector = Optional(str)
    cvss_score = Optional(float)
    affected_resources = Set('AffectedResource')


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
    description = Optional(str, 128)
    clients = Set(Client)
    type = Required(str, 5)  # Choice
    reports = Set(Report)


class Solution(db.Entity):
    id = PrimaryKey(int, auto=True)
    context = Optional(str, 32, default='generic')
    solution = Optional(LongStr)
    finding_template = Required(FindingTemplate)


class Image(db.Entity):
    id = PrimaryKey(int, auto=True)
    path = Optional(str)
    name = Optional(str)
    assessment = Required(Assessment)


class Approval(db.Entity):
    id = PrimaryKey(int, auto=True)
    date = Required(datetime, default=lambda: datetime.now())
    assessment = Required(Assessment)
    user = Required('User')


class User(db.Entity):
    id = PrimaryKey(int, auto=True)
    approvals = Set(Approval)


if __name__ == '__main__':
    db.bind(provider='sqlite', filename='/tmp/database.sqlite', create_db=True)
    db.generate_mapping(create_tables=True)
