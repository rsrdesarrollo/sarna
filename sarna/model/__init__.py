import os
from collections import Counter
from datetime import datetime
from typing import *
from uuid import uuid4

import inflection
import pyotp
from cvsslib import cvss3, calculate_vector
from flask_login import login_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from rfc3986.uri import URIReference
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Query
from werkzeug.security import generate_password_hash, check_password_hash

from sarna.core import app
from sarna.core.config import config
from sarna.model.enumerations import *
from sarna.model.sql_types.enum import Enum
from sarna.model.sql_types.guid import GUID

db = SQLAlchemy(app)
migrate = Migrate(app, db)


@app.after_request
def auto_commit(resp):
    db.session.commit()
    return resp


class Base(object):
    query: Query

    @declared_attr
    def __tablename__(cls):
        return inflection.underscore(cls.__name__).lower()

    def __init__(self, *args, **kwargs):
        pass

    def set(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)

    def to_dict(self):
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)

        return d

    def delete(self, commit=True):
        db.session.delete(self)
        if commit:
            db.session.commit()


__all__ = [
    'db', 'Client', 'Assessment', 'FindingTemplate', 'FindingTemplateTranslation',
    'Active', 'AffectedResource', 'Finding', 'Template', 'Solution', 'Image',
    'User'
]

"""
Client
"""

client_management = db.Table(
    'client_management',
    db.Column('managed_client_id', db.Integer, db.ForeignKey('client.id'), primary_key=True),
    db.Column('manager_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

client_audit = db.Table(
    'client_audit',
    db.Column('audited_client_id', db.Integer, db.ForeignKey('client.id'), primary_key=True),
    db.Column('auditor_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class Client(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    short_name = db.Column(db.String(64), nullable=False)
    long_name = db.Column(db.String(128), nullable=False)

    assessments = db.relationship('Assessment', back_populates='client', cascade='all')
    templates = db.relationship('Template', backref='client', cascade='all')

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship("User", back_populates="created_clients", uselist=False)

    managers = db.relationship('User', secondary=client_management, back_populates='managed_clients')
    auditors = db.relationship('User', secondary=client_audit, back_populates='audited_clients')

    def template_path(self):
        return os.path.join(config.TEMPLATES_PATH, str(self.id))


"""
Assessment
"""

auditor_approval = db.Table(
    'auditor_approval',
    db.Column('approving_user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('approved_assessment_id', db.Integer, db.ForeignKey('assessment.id'), primary_key=True),
    db.Column('approved_at', db.DateTime, default=lambda: datetime.now(), nullable=False)
)

assessment_audit = db.Table(
    'assessment_audit',
    db.Column('audited_assessment_id', db.Integer, db.ForeignKey('assessment.id'), primary_key=True),
    db.Column('auditor_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class Assessment(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(GUID, default=uuid4, unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    platform = db.Column(db.String(64), nullable=False)
    lang = db.Column(Enum(Language), nullable=False)
    type = db.Column(Enum(AssessmentType), nullable=False)
    status = db.Column(Enum(AssessmentStatus), nullable=False)

    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, back_populates="assessments", uselist=False)

    findings = db.relationship('Finding', back_populates='assessment')
    actives = db.relationship('Active', back_populates='assessment', cascade='all')
    images = db.relationship('Image', back_populates='assessment', cascade='all')

    creation_date = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    estimated_hours = db.Column(db.Integer)
    effective_hours = db.Column(db.Integer)

    approvals = db.relationship('User', secondary=auditor_approval, back_populates='approvals')

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship("User", back_populates="created_assessments", uselist=False)

    auditors = db.relationship('User', secondary=assessment_audit, back_populates='audited_assessments')

    def _aggregate_score(self, field):
        counter = Counter(
            map(
                lambda x: getattr(x, field),
                self.findings
            )
        )

        return [
            counter[Score.Info],
            counter[Score.Low],
            counter[Score.Medium],
            counter[Score.High],
            counter[Score.Critical]
        ]

    def aggregate_finding_status(self):
        counter = Counter(
            map(
                lambda x: x.status,
                self.findings
            )
        )
        return [
            counter[FindingStatus.Pending],
            counter[FindingStatus.Reviewed],
            counter[FindingStatus.Confirmed],
            counter[FindingStatus.False_Positive],
            counter[FindingStatus.Other]
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


class FindingTemplate(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(Enum(FindingType), nullable=False)

    owasp_category = db.Column(Enum(OWASPCategory))
    owisam_category = db.Column(Enum(OWISAMCategory))

    tech_risk = db.Column(Enum(Score), nullable=False)
    business_risk = db.Column(Enum(Score), nullable=False)
    exploitability = db.Column(Enum(Score), nullable=False)
    dissemination = db.Column(Enum(Score), nullable=False)
    solution_complexity = db.Column(Enum(Score), nullable=False)

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', back_populates='created_findings', uselist=False)

    solutions = db.relationship('Solution', back_populates='finding_template', cascade='all')
    translations = db.relationship('FindingTemplateTranslation', back_populates='finding_template', cascade='all')

    @property
    def langs(self):
        return {t.lang for t in self.translations}


class FindingTemplateTranslation(Base, db.Model):
    lang = db.Column(Enum(Language), primary_key=True)
    finding_template_id = db.Column(db.Integer, db.ForeignKey('finding_template.id'), primary_key=True)
    finding_template = db.relationship(FindingTemplate, back_populates='translations', uselist=False)

    title = db.Column(db.String(128), nullable=False)
    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())


"""
Actives
"""


class Active(Base, db.Model):
    __table_args__ = (db.UniqueConstraint('assessment_id', 'name'),)

    id = db.Column(db.Integer, primary_key=True)

    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'))
    assessment = db.relationship(Assessment, uselist=False)

    name = db.Column(db.String(128))

    active_resources = db.relationship('AffectedResource', back_populates='active')

    @property
    def uris(self):
        for resource in self.active_resources:
            yield resource.uri


finding_affected_resource = db.Table(
    'finding_affected_resource',
    db.Column('affected_resource_id', db.Integer, db.ForeignKey('affected_resource.id'), primary_key=True),
    db.Column('finding_id', db.Integer, db.ForeignKey('finding.id'), primary_key=True)
)


class AffectedResource(Base, db.Model):
    __table_args__ = (db.UniqueConstraint('active_id', 'route'),)

    id = db.Column(db.Integer, primary_key=True)

    active_id = db.Column(db.Integer, db.ForeignKey('active.id'))
    active = db.relationship(Active, uselist=False, back_populates='active_resources')

    route = db.Column(db.String(256), default='/')

    findings = db.relationship('Finding', secondary=finding_affected_resource)

    @property
    def uri(self):
        return "{}{}".format(self.active.name, self.route or '')


class Finding(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(Enum(FindingType), nullable=False)  # FindingType)

    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'))
    assessment = db.relationship(Assessment, back_populates='findings', uselist=False)

    template_id = db.Column(db.Integer, db.ForeignKey('finding_template.id'))
    template = db.relationship(FindingTemplate, uselist=False)

    title = db.Column(db.String(128), nullable=False)
    status = db.Column(Enum(FindingStatus), nullable=False, default=FindingStatus.Pending)

    owasp_category = db.Column(Enum(OWASPCategory))
    owisam_category = db.Column(Enum(OWISAMCategory))

    description = db.Column(db.String())
    solution = db.Column(db.String())

    tech_risk = db.Column(Enum(Score), nullable=False)
    business_risk = db.Column(Enum(Score), nullable=False)
    exploitability = db.Column(Enum(Score), nullable=False)
    dissemination = db.Column(Enum(Score), nullable=False)
    solution_complexity = db.Column(Enum(Score), nullable=False)

    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)

    affected_resources = db.relationship(AffectedResource, secondary=finding_affected_resource)

    cvss_v3_vector = db.Column(db.String(128))

    def update_affected_resources(self, resources: Collection[AnyStr]):
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

            resource_rute = resource_rute or '/'
            active = Active.query.filter_by(
                assessment=self.assessment,
                name=active_name
            ).first()

            if not active:
                active = Active(assessment=self.assessment, name=active_name)

            affected_resource = AffectedResource.query.filter_by(
                active=active, route=resource_rute
            ).first()

            if not affected_resource:
                affected_resource = AffectedResource(active=active, route=resource_rute)
                active.active_resources.append(affected_resource)

            if affected_resource and affected_resource not in self.affected_resources:
                self.affected_resources.append(affected_resource)

            db.session.commit()

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
            business_risk=template.business_risk,
            exploitability=template.exploitability,
            dissemination=template.dissemination,
            solution_complexity=template.solution_complexity,

            owasp_category=template.owasp_category,
            owisam_category=template.owisam_category,

            template=template,

            title=translation.title,
            definition=translation.definition,
            references=translation.references,
            description=translation.description,

            assessment=assessment
        )


class Template(Base, db.Model):
    name = db.Column(db.String(32), primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), primary_key=True)

    description = db.Column(db.String(128))
    file = db.Column(db.String(128), nullable=False)


class Solution(Base, db.Model):
    name = db.Column(db.String(32), primary_key=True)
    finding_template_id = db.Column(db.Integer, db.ForeignKey('finding_template.id'), primary_key=True)
    finding_template = db.relationship(FindingTemplate, back_populates='solutions', uselist=False)

    lang = db.Column(Enum(Language), nullable=False)
    text = db.Column(db.String(), nullable=False)


class Image(Base, db.Model):
    name = db.Column(db.String(128), primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), primary_key=True)
    assessment = db.relationship(Assessment, back_populates='images', uselist=False)

    label = db.Column(db.String())


class User(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True)
    is_admin = db.Column(db.Boolean(), default=False, nullable=False)
    source = db.Column(Enum(AuthSource), default=AuthSource.database, nullable=False)
    passwd = db.Column(db.String(128))

    creation_date = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    last_access = db.Column(db.DateTime)

    is_locked = db.Column(db.Boolean(), default=False, nullable=False)
    otp_enabled = db.Column(db.Boolean(), default=False, nullable=False)
    otp_seed = db.Column(db.String(16))

    managed_clients = db.relationship(Client, secondary=client_management, back_populates='managers')
    created_clients = db.relationship(Client, back_populates="creator")
    audited_clients = db.relationship(Client, secondary=client_audit, back_populates='auditors')

    approvals = db.relationship(Assessment, secondary=auditor_approval, back_populates='approvals')
    created_assessments = db.relationship(Assessment, back_populates="creator")
    audited_assessments = db.relationship(Assessment, secondary=assessment_audit, back_populates='auditors')

    created_findings = db.relationship(FindingTemplate, back_populates='creator')

    @property
    def name(self):
        return self.username

    def owns(self, obj):
        if isinstance(obj, Client):
            return obj in self.created_clients
        if isinstance(obj, Assessment):
            return obj in self.created_assessments
        elif isinstance(obj, FindingTemplate):
            return obj in self.created_findings

        return False

    def manages(self, obj):
        if self.owns(obj):
            return True

        if isinstance(obj, Client):
            return obj in self.managed_clients

        return False

    def audits(self, obj):
        if self.owns(obj) or self.manages(obj):
            return True

        if isinstance(obj, Client):
            return obj in self.audited_clients
        elif isinstance(obj, Assessment):
            return obj in self.audited_assessments

        return False

    def login(self):
        self.last_access = datetime.now()
        db.session.commit()
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
        db.session.commit()

    def check_password(self, password):
        return check_password_hash(self.passwd, password)

    def generate_otp(self):
        if self.otp_enabled:
            raise ValueError('otp already set')

        self.otp_seed = pyotp.random_base32()
        db.session.commit()
        return pyotp.totp.TOTP(self.otp_seed).provisioning_uri(self.username, issuer_name="SARNA")

    def enable_otp(self, otp):
        if self.otp_enabled:
            raise ValueError('otp already set')

        self.otp_enabled = self.check_otp(otp)
        db.session.commit()
        return self.otp_enabled

    def disable_otp(self, otp):
        if not self.otp_enabled:
            raise ValueError('otp already disabled')

        self.otp_enabled = self.check_otp(otp)
        db.session.commit()
        return not self.otp_enabled

    def confirm_otp(self, otp):
        if not self.otp_enabled:
            raise ValueError('otp not set')

        return self.check_otp(otp)

    def check_otp(self, otp):
        totp = pyotp.TOTP(self.otp_seed)
        return totp.verify(otp)
