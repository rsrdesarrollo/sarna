from sarna.model.base import Base, db
from sarna.model.enums import Score, WSTG, MSTG, OWISAMCategory, FindingType, Language, CWE, ASVS, MASVS
from sarna.model.sql_types import Enum
from flask_wtf import FlaskForm

__all__ = ['FindingTemplateMobileTest', 'FindingTemplateWebTest', 'FindingTemplateMobileRequirement',
           'FindingTemplateWebRequirement', 'FindingTemplateTranslation', 'FindingTemplate', 'Solution',
           'FindingTemplateCWE']


class FindingTemplate(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(Enum(FindingType), nullable=False)

    owisam_category = db.Column(Enum(OWISAMCategory))

    tech_risk = db.Column(Enum(Score), default=Score.NA)
    business_risk = db.Column(Enum(Score), default=Score.NA)
    exploitability = db.Column(Enum(Score), default=Score.NA)
    dissemination = db.Column(Enum(Score), default=Score.NA)
    solution_complexity = db.Column(Enum(Score), default=Score.NA)

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
        if score <  1:
            return Score.Info
        elif 1 <= score < 4:
            return Score.Low
        elif 4 <= score < 7:
            return Score.Medium
        elif 7 <= score < 9:
            return Score.High
        else:
            return Score.Critical

    cwe_refs = db.relationship('FindingTemplateCWE', back_populates='finding_template')
    web_requirements = db.relationship('FindingTemplateWebRequirement', back_populates='finding_template')
    mobile_requirements = db.relationship('FindingTemplateMobileRequirement', back_populates='finding_template')
    wstg_refs = db.relationship('FindingTemplateWebTest', back_populates='finding_template')
    mstg_refs = db.relationship('FindingTemplateMobileTest', back_populates='finding_template')

    def update_one_to_manies(self, form: FlaskForm):
        # CWE
        data_cwe = {k: v for k, v in dict(form.data).items() if k in FindingTemplateCWE.__dict__}
        if data_cwe:
            data_cwe = data_cwe['cwe_ref']
            # Delete current relation
            for ref in self.cwe_refs:
                if not ref.cwe_ref in data_cwe:
                    ref.delete()
                else:
                    data_cwe.remove(ref.cwe_ref)
            # Create new refs
            for ref in data_cwe:
                FindingTemplateCWE(finding_template=self, cwe_ref=ref)
        # ASVS
        data_asvs = {k: v for k, v in dict(form.data).items() if k in FindingTemplateWebRequirement.__dict__}
        if data_asvs:
            data_asvs = data_asvs['asvs_req']
            # Delete current relation
            for requirement in self.web_requirements:
                if not requirement.asvs_req in data_asvs:
                    requirement.delete()
                else:
                    data_asvs.remove(requirement.asvs_req)
            # Create new requirements
            for asvs in data_asvs:
                FindingTemplateWebRequirement(finding_template=self, asvs_req=asvs)
        # MASVS
        data_masvs = {k: v for k, v in dict(form.data).items() if k in FindingTemplateMobileRequirement.__dict__}
        if data_masvs:
            data_masvs = data_masvs['masvs_req']
            # Delete current relation
            for requirement in self.mobile_requirements:
                if not requirement.masvs_req in data_masvs:
                    requirement.delete()
                else:
                    data_masvs.remove(requirement.masvs_req)
            # Create new requirements
            for masvs in data_masvs:
                FindingTemplateMobileRequirement(finding_template=self, masvs_req=masvs)
        # WSTG
        data_wstg = {k: v for k, v in dict(form.data).items() if k in FindingTemplateWebTest.__dict__}
        if data_wstg:
            data_wstg = data_wstg['wstg_ref']
            # Delete current relation
            for ref in self.wstg_refs:
                if not ref.wstg_ref in data_wstg:
                    ref.delete()
                else:
                    data_wstg.remove(ref.wstg_ref)
            # Create new refs
            for wstg in data_wstg:
                FindingTemplateWebTest(finding_template=self, wstg_ref=wstg)
        # MSTG
        data_mstg = {k: v for k, v in dict(form.data).items() if k in FindingTemplateMobileTest.__dict__}
        if data_mstg:
            data_mstg = data_mstg['mstg_ref']
            # Delete current relation
            for ref in self.mstg_refs:
                if not ref.mstg_ref in data_mstg:
                    ref.delete()
                else:
                    data_mstg.remove(ref.mstg_ref)
            # Create new refs
            for mstg in data_mstg:
                FindingTemplateMobileTest(finding_template=self, mstg_ref=mstg)

    def display_one_to_manies(self, data: dict):
        if not data:
            data = []
        # CWE
        cwe_refs = []
        for ref in self.cwe_refs:
            cwe_refs.append(CWE(ref.cwe_ref))
        data['cwe_ref'] = cwe_refs
        # ASVS
        web_requirements = []
        for requirement in self.web_requirements:
            web_requirements.append(ASVS(requirement.asvs_req))
        data['asvs_req'] = web_requirements
        # MASVS
        mobile_requirements = []
        for requirement in self.mobile_requirements:
            mobile_requirements.append(MASVS(requirement.masvs_req))
        data['masvs_req'] = mobile_requirements
        # WSTG
        wstg_refs = []
        for ref in self.wstg_refs:
            wstg_refs.append(WSTG(ref.wstg_ref))
        data['wstg_ref'] = wstg_refs
        # MSTG
        mstg_refs = []
        for ref in self.mstg_refs:
            mstg_refs.append(MSTG(ref.mstg_ref))
        data['mstg_ref'] = mstg_refs

        return data


class FindingTemplateWebRequirement(Base, db.Model):
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    asvs_req = db.Column(Enum(ASVS), primary_key=True)
    finding_template = db.relationship('FindingTemplate', back_populates='web_requirements')


class FindingTemplateMobileRequirement(Base, db.Model):
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    masvs_req = db.Column(Enum(MASVS), primary_key=True)
    finding_template = db.relationship('FindingTemplate', back_populates='mobile_requirements')


class FindingTemplateWebTest(Base, db.Model):
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    wstg_ref = db.Column(Enum(WSTG), primary_key=True)
    finding_template = db.relationship('FindingTemplate', back_populates='wstg_refs')


class FindingTemplateMobileTest(Base, db.Model):
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    mstg_ref = db.Column(Enum(MSTG), primary_key=True)
    finding_template = db.relationship('FindingTemplate', back_populates='mstg_refs')


class FindingTemplateCWE(Base, db.Model):
    finding_template_id = db.Column(
        db.Integer,
        db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    cwe_ref = db.Column(Enum(CWE), primary_key=True)
    finding_template = db.relationship('FindingTemplate', back_populates='cwe_refs')


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
