import os
from datetime import datetime, date
from uuid import UUID, uuid4

from cvsslib import cvss3, calculate_vector
from pony.orm.core import *

from sarna import config
from .aux import *

db = Database()


class Client(db.Entity):
    id = PrimaryKey(UUID, default=uuid4)
    assessments = Set('Assessment')
    templates = Set('Template')
    short_name = Required(str, 64)
    long_name = Required(str, 128)
    users = Set('User')

    def template_path(self):
        return os.path.join(config.TEMPLATES_PATH, str(self.id))


class Assessment(db.Entity):
    id = PrimaryKey(int, auto=True)
    uuid = Required(UUID, default=uuid4, unique=True)
    name = Required(str, 32)
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

    def evidence_path(self):
        return os.path.join(config.EVIDENCES_PATH, str(self.uuid))


class FindingTemplate(db.Entity):
    id = PrimaryKey(int, auto=True)
    name = Required(str, 64)
    type = Required(FindingType)
    owasp_category = Optional(OWASPCategory)
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
    assessment = Required(Assessment, index=True)
    template = Optional(FindingTemplate)

    title = Required(str)
    status = Required(FindingStatus, default=FindingStatus.Pending)
    owasp_category = Optional(OWASPCategory)

    description = Optional(LongStr)
    solution = Optional(LongStr)

    tech_risk = Required(Score)
    business_risk = Optional(Score)
    exploitability = Optional(Score)
    dissemination = Required(Score)
    solution_complexity = Required(Score)

    definition = Required(LongStr)
    references = Required(LongStr)

    affected_resources = Set('AffectedResource')

    cvss_v3_vector = Optional(str, 128)

    @property
    def cvss_v3_score(self):
        try:
            return calculate_vector(self.cvss_v3_vector, cvss3)[0]
        except:
            return 0

    @property
    def cvss_v3_severity(self):
        score = self.cvss_v3_score
        if score == 0:
            return Score.NA
        elif 0 < score < 4:
            return Score.Low
        elif 4 <= score < 7:
            return Score.Medium
        elif 7 <= score < 9:
            return Score.High
        else:
            return Score.Critical

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
            owasp_category=template.owasp_category,
            template=template,

            title=translation.title,
            definition=translation.definition,
            references=translation.references,

            assessment=assessment
        )


class Active(db.Entity):
    name = PrimaryKey(str)
    affected_resources = Set('AffectedResource')
    assessment = Required(Assessment)

    @property
    def urls(self):
        for resource in self.affected_resources:
            yield resource.url


class AffectedResource(db.Entity):
    id = PrimaryKey(int, auto=True)
    active = Required(Active)
    route = Optional(str)
    findings = Set(Finding)
    composite_key(active, route)

    @property
    def url(self):
        return os.path.join(self.active.name, self.route)


class Template(db.Entity):
    name = Required(str, 32)
    client = Required(Client)
    description = Optional(str, 128)
    file = Required(str, 128)
    PrimaryKey(client, name)


class Solution(db.Entity):
    name = Required(str, 32)
    lang = Required(Language)
    text = Required(LongStr)
    finding_template = Required(FindingTemplate)
    PrimaryKey(finding_template, name)


class Image(db.Entity):
    name = Required(str)
    assessment = Required(Assessment)
    label = Optional(str)
    PrimaryKey(assessment, name)


class Approval(db.Entity):
    id = PrimaryKey(UUID, default=uuid4)
    date = Required(datetime, default=lambda: datetime.now())
    assessment = Required(Assessment)
    user = Required('User')


class User(db.Entity):
    username = PrimaryKey(str)
    is_admin = Required(bool, default=False)
    assessments = Set(Assessment)
    clients = Set(Client)
    approvals = Set(Approval)


def init_database():
    from os import path

    database_path = path.join(config.DATABASE_PATH, 'database.sqlite')

    db.bind(provider='sqlite', filename=database_path, create_db=True)

    for cls in (Language, AssessmentStatus, AssessmentType, FindingStatus, FindingType, Score, OWASPCategory):
        db.provider.converter_classes.append((cls, ChoiceEnumConverter))

    db.generate_mapping(create_tables=True)


if __name__ == '__main__':
    init_database()
