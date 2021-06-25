import re
import requests

from sarna.model.base import Base, db
from sarna.model.enums import Score, OWASPCategory, OWISAMCategory, FindingType, Language
from sarna.model.enums.category import OWASPMobileTop10Category
from sarna.model.sql_types import Enum
from sarna.core.config import config

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

    solutions = db.relationship('Solution', back_populates='finding_template')
    translations = db.relationship('FindingTemplateTranslation', back_populates='finding_template')

    cvss_v3_vector = db.Column(db.String(128))
    cvss_v3_score = db.Column(db.Float, default=0.0, nullable=False)

    @property
    def langs(self):
        return {t.lang for t in self.translations}

    @property
    def cvss_v3_severity(self):
        score = self.cvss_v3_score
        if score == 0:
            return Score.Info
        elif 0 < score < 4:
            return Score.Low
        elif 4 <= score < 7:
            return Score.Medium
        elif 7 <= score < 9:
            return Score.High
        else:
            return Score.Critical

    def check_translations_references_urls(self):
        for translation in self.translations:
            translation.check_references_urls()


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

    def check_references_urls(self):
        url_regex = r"\[.+\]\((.+)\)"
        refs_lines = self.references.splitlines()

        for i, ref_line in enumerate(refs_lines):
            match_url = re.search(url_regex, ref_line)

            if match_url:
                ref = match_url.group(0)
                url = match_url.group(1)
                try:
                    req = requests.head(url, allow_redirects=True, timeout=config.BROKEN_REFS_REQ_TIMEOUT)
                    req.raise_for_status()

                    refs_lines[i] = ref_line.replace(config.BROKEN_REFS_TOKEN, "", 1)
                except:
                    if config.BROKEN_REFS_TOKEN not in ref_line:
                        refs_lines[i] = ref_line.replace(ref, f"{ref}{config.BROKEN_REFS_TOKEN}", 1)

        self.references = "\r\n".join(refs_lines)
        db.session.commit()


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
