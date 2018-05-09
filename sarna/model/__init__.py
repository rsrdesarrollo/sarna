from datetime import datetime, date
from pony.orm import *
from .aux import *

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
    lang = Required(Language)
    type = Required(AssessmentType)
    platform = Required(str, 64)
    status = Required(AssessmentStatus)
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

    def _aggregate_score(self, field):
        return [
            count(f for f in self.findings if getattr(f, field) == Score.Info),
            count(f for f in self.findings if getattr(f, field) == Score.Low),
            count(f for f in self.findings if getattr(f, field) == Score.Medium),
            count(f for f in self.findings if getattr(f, field) == Score.High),
            count(f for f in self.findings if getattr(f, field) == Score.Critical)
        ]

    def aggregate_finding_status(self):
        return [
            count(f for f in self.findings if f.status == FindingStatus.Pending),
            count(f for f in self.findings if f.status == FindingStatus.Reviewed),
            count(f for f in self.findings if f.status == FindingStatus.Confirmed),
            count(f for f in self.findings if f.status == FindingStatus.False_Positive),
            count(f for f in self.findings if f.status == FindingStatus.Other)
        ]

    def aggregate_technical_risk(self):
        return self._aggregate_score('tech_risk')

    def aggregate_business_risk(self):
        return self._aggregate_score('business_risk')


class Report(db.Entity):
    id = PrimaryKey(int, auto=True)
    assessment = Required(Assessment)
    name = Required(str, 64)
    template = Required('Template')


class FindingTemplate(db.Entity):
    id = PrimaryKey(int, auto=True)
    name = Required(str, 64)
    type = Required(FindingType)
    tech_risk = Required(Score)  # [0 to 4]
    dissemination = Required(Score)  # [0 to 4]
    solution_complexity = Required(Score)  # [0 to 4]
    solutions = Set('Solution')
    translations = Set('FindingTemplateTranslation')

    findings = Set('Finding')

    @property
    def langs(self):
        return [t.lang for t in self.translations]


class FindingTemplateTranslation(db.Entity):
    lang = Required(Language)
    title = Required(str)
    definition = Required(LongStr)
    references = Required(LongStr)
    finding = Required(FindingTemplate)
    PrimaryKey(finding, lang)


class Finding(db.Entity):
    id = PrimaryKey(int, auto=True)
    name = Required(str, 64)
    type = Required(FindingType)

    tech_risk = Required(Score)  # [0 to 4]
    business_risk = Optional(Score)  # [0 to 4]
    exploitability = Optional(Score)  # [0 to 4]
    dissemination = Required(Score)  # [0 to 4]
    solution_complexity = Required(Score)  # [0 to 4]

    template = Optional(FindingTemplate)

    title = Required(str)
    definition = Required(LongStr)
    references = Required(LongStr)

    affected_resources = Set('AffectedResource')
    status = Required(FindingStatus, default=FindingStatus.Pending)
    assessment = Required(Assessment, index=True)

    description = Optional(LongStr)
    solution = Optional(LongStr)

    cvss_v3_vector = Optional(str, 124)
    cvss_score = Optional(float)

    @classmethod
    def build_from_template(cls, template: FindingTemplate, assessment: Assessment):
        lang = assessment.lang
        translation: FindingTemplateTranslation = None
        for t in template.translations:
            translation = t
            if t.lang == lang:
                break

        return Finding(
            name=template.name,
            type=template.type,
            tech_risk=template.tech_risk,
            dissemination=template.dissemination,
            solution_complexity=template.solution_complexity,
            template=template,

            title=translation.title,
            definition=translation.definition,
            references=translation.references,

            assessment=assessment
        )


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
    # type = Required(str, 5)  # Choice


class Solution(db.Entity):
    name = Required(str, 32)
    lang = Required(Language)
    text = Required(LongStr)
    finding_template = Required(FindingTemplate)
    PrimaryKey(finding_template, name)


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
    from os import path

    db.bind(provider='sqlite', filename=path.abspath('./database/database.sqlite'), create_db=True)

    for cls in (Language, AssessmentStatus, AssessmentType, FindingStatus, FindingType, Score):
        db.provider.converter_classes.append((cls, ChoiceEnumConverter))

    db.generate_mapping(create_tables=True)


if __name__ == '__main__':
    init_database()
