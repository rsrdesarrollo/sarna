import os
from datetime import datetime
from typing import *
from uuid import uuid4

import pyotp
from cvsslib import cvss3, calculate_vector
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from rfc3986.uri import URIReference
from sqlalchemy.ext.associationproxy import association_proxy
from werkzeug.security import generate_password_hash, check_password_hash

from sarna.core import app
from sarna.core.config import config
from sarna.model.enumerations import *
from sarna.model.guid import GUID

db = SQLAlchemy(app)
migrate = Migrate(app, db)

__all__ = [
    'db', 'Client', 'Assessment', 'FindingTemplate', 'FindingTemplateTranslation',
    'Active', 'AffectedResource', 'Finding', 'Template', 'Solution', 'Image',
    'User'
]

"""
Client
"""

client_management = db.Table('client_management',
    db.Column('managed_client_id', db.Integer, db.ForeignKey('client.id'), primary_key=True),
    db.Column('manager_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

client_audit = db.Table('client_audit',
    db.Column('audited_client_id', db.Integer, db.ForeignKey('client.id'), primary_key=True),
    db.Column('auditor_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class Client(db.Model):
    __tablename__ = 'client'
    id = db.Column(db.Integer, primary_key=True)
    assessments = db.relationship('Assessment', back_populates='client')
    templates = db.relationship('Template', back_populates='client')
    short_name = db.Column(db.String(64), nullable=False)
    long_name = db.Column(db.String(128), nullable=False)

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship("User", back_populates="created_clients", uselist=False)

    managers = db.relationship('User', secondary=client_management, back_populates='managed_clients')
    auditors = db.relationship('User', secondary=client_audit, back_populates='audited_clients')

    def template_path(self):
        return os.path.join(config.TEMPLATES_PATH, str(self.id))


"""
Assessment
"""

auditor_approval = db.Table('auditor_approval',
    db.Column('approving_user_id', db.ForeignKey('user.id', primary_key=True)),
    db.Column('approved_assessment_id', db.ForeignKey('assessment.id', primary_key=True)),
    db.Column('approved_at', db.DateTime, default=lambda: datetime.now(), nullable=False)
)

assessment_audit = db.Table('assessment_audit',
    db.Column('audited_assessment_id', db.Integer, db.ForeignKey('assessment.id', primary_key=True)),
    db.Column('auditor_id', db.Integer, db.ForeignKey('user.id', primary_key=True))
)


class Assessment(db.Model):
    __tablename__ = 'assessment'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(GUID, default=uuid4, unique=True, nullable=False)
    name = db.Column(db.String(32), nullable=False)
    platform = db.Column(db.String(64), nullable=False)
    lang = db.Column(db.Enum(Language), nullable=False)
    type = db.Column(db.Enum(AssessmentType), nullable=False)
    status = db.Column(db.Enum(AssessmentStatus), nullable=False)

    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship("User", back_populates="assessments", uselist=False)

    actives = db.relationship('Active', back_populates='assessment')
    findings = db.relationship('Finding', back_populates='assessment')
    images = db.relationship('Image', back_populates='assessment')

    creation_date = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    estimated_hours = db.Column(db.Integer)
    effective_hours = db.Column(db.Integer)

    approvals = db.relationship('User', secondary=auditor_approval, back_populates='approved_assessments')

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship("User", back_populates="created_assessments", uselist=False)

    auditors = db.relationship('User', secondary=assessment_audit, back_populates='audited_assessments')

    def _aggregate_score(self, field):
        return [
            self.findings.filter(Finding.has(**{field: Score.Info})).count(),
            self.findings.filter(Finding.has(**{field: Score.Low})).count(),
            self.findings.filter(Finding.has(**{field: Score.Medium})).count(),
            self.findings.filter(Finding.has(**{field: Score.High})).count(),
            self.findings.filter(Finding.has(**{field: Score.Critical})).count()
        ]

    def aggregate_finding_status(self):
        return [
            self.findings.filter(Finding.has(status=FindingStatus.Pending)).count(),
            self.findings.filter(Finding.has(status=FindingStatus.Reviewed)).count(),
            self.findings.filter(Finding.has(status=FindingStatus.Confirmed)).count(),
            self.findings.filter(Finding.has(status=FindingStatus.False_Positive)).count(),
            self.findings.filter(Finding.has(status=FindingStatus.Other)).count()
        ]

    def aggregate_technical_risk(self):
        return self._aggregate_score('tech_risk')

    def aggregate_business_risk(self):
        return self._aggregate_score('business_risk')

    def evidence_path(self):
        return os.path.join(config.EVIDENCES_PATH, str(self.uuid))


"""
Finding template
"""


class FindingTemplate(db.Model):
    __tablename__ = 'finding_template'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(db.Enum(FindingType), nullable=False)
    owasp_category = db.Column(db.Enum(OWASPCategory))
    tech_risk = db.Column(db.Enum(Score), nullable=False)
    dissemination = db.Column(db.Enum(Score), nullable=False)
    solution_complexity = db.Column(db.Enum(Score), nullable=False)

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', back_populates='created_findings', uselist=False)

    solutions = db.relationship('Solution')
    translations = db.relationship('FindingTemplateTranslation')

    @property
    def langs(self):
        return self.translations.distinct(FindingTemplateTranslation.lang)


class FindingTemplateTranslation(db.Model):
    __tablename__ = 'finding_template_translation'

    lang = db.Column(db.Enum(Language), primary_key=True)
    finding_id = db.Column(db.ForeignKey('finding_template.id'), primary_key=True)

    title = db.Column(db.String(), nullable=False)
    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())


"""
Actives
"""


class Active(db.Model):
    __tablename__ = 'active'
    assessment_id = db.Column(db.ForeignKey('assessment.id'), primary_key=True)
    name = db.Column(db.String(), primary_key=True)

    affected_resources = association_proxy('active_resources', 'affected_resources')

    @property
    def uris(self):
        for resource in self.affected_resources.all():
            yield resource.uri


class AffectedResource(db.Model):
    __tablename__ = 'affected_resource'
    active_id = db.Column(db.String, db.ForeignKey('active.name'), primary_key=True)
    active = db.relationship(Active, backref='active_resources', uselist=False)

    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'), primary_key=True)
    finding = db.relationship(Active, backref='finding_resources', uselist=False)

    route = db.Column(db.String(), nullable=True)
    db.UniqueConstraint('active_id', 'route')

    @property
    def uri(self):
        return "{}{}".format(self.active.name, self.route or '')


class Finding(db.Model):
    __tablename__ = 'finding'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(db.Enum(FindingType), nullable=False)  # FindingType)

    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'))
    assessment = db.relationship(Assessment, back_populates='findings', uselist=False)

    template_id = db.Column(db.Integer, db.ForeignKey('finding_template.id'))
    template = db.relationship(FindingTemplate, uselist=False)

    title = db.Column(db.String(), nullable=False)
    status = db.Column(db.Enum(FindingStatus), nullable=False, default=FindingStatus.Pending)
    owasp_category = db.Column(db.Enum(OWASPCategory))

    description = db.Column(db.String())
    solution = db.Column(db.String())

    tech_risk = db.Column(db.Enum(Score), nullable=False)
    business_risk = db.Column(db.Enum(Score))
    exploitability = db.Column(db.Enum(Score))
    dissemination = db.Column(db.Enum(Score), nullable=False)
    solution_complexity = db.Column(db.Enum(Score), nullable=False)

    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)

    affected_resources = association_proxy('finding_resources', 'affected_resources')

    cvss_v3_vector = db.Column(db.String(128))

    def update_affected_resources(self, resources: Collection[AnyStr]):
        ## TODO: migrate to SQLAlchemy
        resource_uris = []
        for resource in resources:
            resource = resource.strip()
            if not resource:
                continue  # Skip empty lines
            resource_uri = URIReference.from_string(resource)
            if resource_uri.is_valid(require_scheme=True, require_path=True):
                if resource_uri.authority is not None or resource_uri.scheme == 'urn':
                    resource_uris.append(resource_uri)
                    continue

            raise ValueError('Invalid formatted URI: "{}"'.format(resource.strip()))

        self.affected_resources.clear()
        for resource in resource_uris:
            if resource.authority is not None:
                # URL
                active_name = "{}://{}".format(resource.scheme, resource.authority)
                resource_rute = resource.path
                if resource.query:
                    resource_rute += "?" + resource.query
                if resource.fragment:
                    resource_rute += "#" + resource.fragment
            elif resource.scheme == 'urn':
                # URN
                active_name = "{}:{}".format(resource.scheme, resource.path)
                resource_rute = None
            else:
                # TODO: this should never happen. Make some warning.
                continue

            try:
                active = Active[self.assessment, active_name]
                affected_resource = len(
                    r for r in AffectedResource if r.active == active and r.route == resource_rute
                ).first()

                if not affected_resource:
                    affected_resource = AffectedResource(active=active, route=resource_rute)

            except Exception as objectNotFound:
                active = Active(assessment=self.assessment, name=active_name)
                affected_resource = AffectedResource(active=active, route=resource_rute)

            db.session.commit()
            self.affected_resources.add(affected_resource)

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
        # TODO: Migrate to SQLAlchemy
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
            description=translation.description,

            assessment=assessment
        )


class Template(db.Model):
    __tablename__ = 'template'
    name = db.Column(db.String(32), primary_key=True)
    client_id = db.Column(db.ForeignKey('client.id'), primary_key=True)

    description = db.Column(db.String(128))
    file = db.Column(db.String(128), nullable=False)


class Solution(db.Model):
    __tablename__ = 'solution'
    name = db.Column(db.String(32), primary_key=True)
    finding_template_id = db.Column(db.ForeignKey('finding_template.id'), primary_key=True)

    lang = db.Column(db.Enum(Language), nullable=False)
    text = db.Column(db.String(), nullable=False)


class Image(db.Model):
    __tablename__ = 'image'
    name = db.Column(db.String(128), primary_key=True)
    assessment_id = db.Column(db.ForeignKey('assessment.id'), primary_key=True)
    label = db.Column(db.String())


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True)
    is_admin = db.Column(db.Boolean(), default=False, nullable=False)
    passwd = db.Column(db.String())

    creation_date = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    last_access = db.Column(db.DateTime)

    is_locked = db.Column(db.Boolean(), default=False, nullable=False)
    otp_enabled = db.Column(db.Boolean(), default=False, nullable=False)
    otp_seed = db.Column(db.String(16))

    ## TODO: approvals = Set(Approval)

    ## TODO: manages = Set('Client', reverse='managers')

    ## TODO: created_clients = Set('Client', reverse='creator')
    ## TODO: created_findings = Set('FindingTemplate', reverse='creator')
    ## TODO: created_assessments = Set('Assessment', reverse='creator')

    ## TODO: audits_assessments = Set('Assessment', reverse='auditors')
    ## TODO: audits_clients = Set('Client', reverse='auditors')

    def login(self):
        from flask_login import login_user
        self.last_access = datetime.now()
        login_user(self)

    def get_id(self):
        return self.username

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    @property
    def is_active(self):
        return not self.is_locked

    def set_passwd(self, passwd):
        self.passwd = generate_password_hash(passwd)

    def check_password(self, password):
        return check_password_hash(self.passwd, password)

    def generate_otp(self):
        if self.otp_enabled:
            raise ValueError('otp already set')

        self.otp_seed = pyotp.random_base32()
        return pyotp.totp.TOTP(self.otp_seed).provisioning_uri(self.username, issuer_name="SARNA")

    def enable_otp(self, otp):
        if self.otp_enabled:
            raise ValueError('otp already set')

        self.otp_enabled = self.check_otp(otp)
        return self.otp_enabled

    def confirm_otp(self, otp):
        if not self.otp_enabled:
            raise ValueError('otp not set')

        return self.check_otp(otp)

    def check_otp(self, otp):
        totp = pyotp.TOTP(self.otp_seed)
        return totp.verify(otp)
