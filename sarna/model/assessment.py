import os
from collections import Counter
from datetime import datetime
from uuid import uuid4

from sarna.core.config import config
from sarna.model.base import Base, db
from sarna.model.client import Client
from sarna.model.enums import Language, AssessmentType, AssessmentStatus, Score, FindingStatus
from sarna.model.sql_types import Enum, GUID

__all__ = ['Assessment', 'Image', 'auditor_approval', 'assessment_audit']

auditor_approval = db.Table(
    'auditor_approval',
    db.Column(
        'approving_user_id',
        db.Integer,
        db.ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    ),
    db.Column(
        'approved_assessment_id',
        db.Integer,
        db.ForeignKey('assessment.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    ),
    db.Column(
        'approved_at',
        db.DateTime,
        default=lambda: datetime.now(),
        nullable=False
    )
)
assessment_audit = db.Table(
    'assessment_audit',
    db.Column(
        'audited_assessment_id',
        db.Integer,
        db.ForeignKey('assessment.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    ),
    db.Column(
        'auditor_id',
        db.Integer,
        db.ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
)


class Assessment(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(GUID, default=uuid4, unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    platform = db.Column(db.String(64), nullable=False)
    lang = db.Column(Enum(Language), nullable=False)
    type = db.Column(Enum(AssessmentType), nullable=False)
    status = db.Column(Enum(AssessmentStatus), nullable=False)

    client_id = db.Column(
        db.Integer,
        db.ForeignKey('client.id', onupdate='CASCADE', ondelete='CASCADE'),
        nullable=False
    )
    client = db.relationship(Client, back_populates="assessments", uselist=False)

    findings = db.relationship('Finding', back_populates='assessment')
    actives = db.relationship('Active', back_populates='assessment')
    images = db.relationship('Image', back_populates='assessment')

    creation_date = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    estimated_hours = db.Column(db.Integer)
    effective_hours = db.Column(db.Integer)

    approvals = db.relationship('User', secondary=auditor_approval, back_populates='approvals')

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
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


class Image(Base, db.Model):
    name = db.Column(db.String(128), primary_key=True)
    assessment_id = db.Column(
        db.Integer,
        db.ForeignKey('assessment.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    assessment = db.relationship(Assessment, back_populates='images', uselist=False)

    label = db.Column(db.String())
