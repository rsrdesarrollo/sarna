from sarna.model.base import Base, db
from sarna.model.enums import Score, OWASPCategory, OWISAMCategory, FindingType, Language
from sarna.model.enums.category import OWASPMobileTop10Category
from sarna.model.sql_types import Enum

__all__ = ['FindingTemplateTranslation', 'FindingTemplate', 'Solution']


class FindingTemplate(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(Enum(FindingType), nullable=False)

    owasp_category = db.Column(Enum(OWASPCategory))
    owasp_mobile_category = db.Column(Enum(OWASPMobileTop10Category))
    owisam_category = db.Column(Enum(OWISAMCategory))

    tech_risk = db.Column(Enum(Score), nullable=False)
    business_risk = db.Column(Enum(Score), nullable=False)
    exploitability = db.Column(Enum(Score), nullable=False)
    dissemination = db.Column(Enum(Score), nullable=False)
    solution_complexity = db.Column(Enum(Score), nullable=False)

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate='CASCADE', ondelete='CASCADE'), nullable=False)
    creator = db.relationship('User', back_populates='created_findings', uselist=False)

    solutions = db.relationship('Solution', back_populates='finding_template', cascade='all')
    translations = db.relationship('FindingTemplateTranslation', back_populates='finding_template', cascade='all')

    @property
    def langs(self):
        return {t.lang for t in self.translations}


class FindingTemplateTranslation(Base, db.Model):
    lang = db.Column(Enum(Language), primary_key=True)
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    finding_template = db.relationship(FindingTemplate, back_populates='translations', uselist=False)

    title = db.Column(db.String(128), nullable=False)
    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())


class Solution(Base, db.Model):
    name = db.Column(db.String(32), primary_key=True)
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    finding_template = db.relationship(FindingTemplate, back_populates='solutions', uselist=False)

    lang = db.Column(Enum(Language), nullable=False)
    text = db.Column(db.String(), nullable=False)
