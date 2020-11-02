import os

from typing import Collection, AnyStr

from rfc3986 import URIReference
from sqlathanor import AttributeConfiguration

from sarna.model.assessment import Assessment
from sarna.model.base import Base, db, supported_serialization
from sarna.model.enums import Score, WSTG, MSTG, OWISAMCategory, FindingType, FindingStatus, CWE, ASVS, MASVS
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation
from sarna.model.sql_types import Enum

from flask_wtf import FlaskForm

__all__ = ['FindingMobileTest', 'FindingWebTest', 'FindingWebRequirement', 'FindingMobileRequirement',
           'Finding', 'Active', 'AffectedResource', 'finding_affected_resource', 'FindingCWE']

finding_affected_resource = db.Table(
    'finding_affected_resource',
    db.Column(
        'affected_resource_id',
        db.Integer,
        db.ForeignKey('affected_resource.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    ),
    db.Column(
        'finding_id',
        db.Integer,
        db.ForeignKey('finding.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
)


class Finding(Base, db.Model):
    __serialization__ = [
        AttributeConfiguration(name='id', csv_sequence=1, **supported_serialization),
        AttributeConfiguration(name='name', **supported_serialization),
        AttributeConfiguration(name='title', **supported_serialization),
        AttributeConfiguration(name='type', **supported_serialization),
        AttributeConfiguration(name='status', **supported_serialization),
        AttributeConfiguration(name='owisam_category', **supported_serialization),
        AttributeConfiguration(name='description', **supported_serialization),
        AttributeConfiguration(name='solution', **supported_serialization),
        AttributeConfiguration(name='tech_risk', **supported_serialization),
        AttributeConfiguration(name='business_risk', **supported_serialization),
        AttributeConfiguration(name='exploitability', **supported_serialization),
        AttributeConfiguration(name='dissemination', **supported_serialization),
        AttributeConfiguration(name='solution_complexity', **supported_serialization),
        AttributeConfiguration(name='definition', **supported_serialization),
        AttributeConfiguration(name='references', **supported_serialization),
        AttributeConfiguration(name='affected_resources', **supported_serialization),
        AttributeConfiguration(name='cvss_v3_vector', **supported_serialization),
        AttributeConfiguration(name='cvss_v3_score', **supported_serialization),
        AttributeConfiguration(name='cvss_v3_severity', **supported_serialization),
        AttributeConfiguration(name='client_finding_id', **supported_serialization),
        AttributeConfiguration(name='client_finding_code', **supported_serialization),
        AttributeConfiguration(name='notes', **supported_serialization),
        AttributeConfiguration(name='cwe', **supported_serialization),
        AttributeConfiguration(name='bugtracking', **supported_serialization)
    ]

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    type = db.Column(Enum(FindingType), nullable=False)

    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id', onupdate='CASCADE', ondelete='CASCADE'))
    assessment = db.relationship(Assessment, back_populates='findings', uselist=False)

    template_id = db.Column(db.Integer, db.ForeignKey('finding_template.id', onupdate='CASCADE', ondelete='SET NULL'))
    template = db.relationship(FindingTemplate, uselist=False)

    title = db.Column(db.String(128), nullable=False)
    status = db.Column(Enum(FindingStatus), nullable=False, default=FindingStatus.Pending)

    owisam_category = db.Column(Enum(OWISAMCategory))

    description = db.Column(db.String())
    solution = db.Column(db.String())

    tech_risk = db.Column(Enum(Score), default=Score.NA)
    business_risk = db.Column(Enum(Score), default=Score.NA)
    exploitability = db.Column(Enum(Score), default=Score.NA)
    dissemination = db.Column(Enum(Score), default=Score.NA)
    solution_complexity = db.Column(Enum(Score), default=Score.NA)

    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)

    affected_resources = db.relationship('AffectedResource', secondary=finding_affected_resource)

    cvss_v3_vector = db.Column(db.String(128))
    cvss_v3_score = db.Column(db.Float, default=0.0, nullable=False)

    client_finding_id = db.Column(db.Integer(), nullable=False)

    notes = db.Column(db.String())

    bugtracking = db.Column(db.String(16))

    def update_affected_resources(self, resources: Collection[AnyStr]):
        resource_uris = []
        for resource in resources:
            resource = resource.strip()
            if not resource:
                continue  # Skip empty lines
            resource_uri = URIReference.from_string(resource)
            if resource_uri.is_valid(require_scheme=True):
                _resource_ok = resource_uri.scheme.lower() in {'http', 'https'} and resource_uri.authority is not None
                _resource_ok = _resource_ok or (resource_uri.scheme == 'urn' and resource_uri.path is not None)
                if _resource_ok:
                    resource_uris.append(resource_uri)
                    continue

            raise ValueError('Invalid formatted URI: "{}"'.format(resource.strip()))

        affected_resources_to_add = set()

        for resource in resource_uris:
            if resource.authority is not None:
                # URL
                active_name = "{}://{}".format(resource.scheme, resource.authority)
                resource_route = resource.path

                if not resource_route:
                    resource_route = "/"

                if resource.query:
                    resource_route += "?" + resource.query

                if resource.fragment:
                    resource_route += "#" + resource.fragment
            elif resource.scheme == 'urn':
                # URN
                resource_name, *path = resource.path.split('/', 1)
                active_name = "{}:{}".format(resource.scheme, resource_name)
                resource_route = "/{}".format(path[0]) if path else None
            else:
                # TODO: this should never happen. Make some warning.
                continue

            active = Active.query.filter_by(
                assessment=self.assessment,
                name=active_name
            ).first()

            if not active:
                active = Active(assessment=self.assessment, name=active_name)
                affected_resource = AffectedResource(active=active, route=resource_route)
                active.active_resources.append(affected_resource)
                db.session.add(active)
                db.session.add(affected_resource)
            else:
                affected_resource = AffectedResource.query.filter_by(
                    active=active, route=resource_route
                ).first()

                if not affected_resource:
                    affected_resource = AffectedResource(active=active, route=resource_route)
                    active.active_resources.append(affected_resource)
                    db.session.add(affected_resource)

            affected_resources_to_add.add(affected_resource)
            db.session.commit()

        for affected_resource in self.affected_resources:
            if affected_resource not in affected_resources_to_add:
                affected_resource.delete_last_reference()

        for affected_resource in affected_resources_to_add:
            self.affected_resources.append(affected_resource)

        db.session.commit()

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

    @property
    def client_finding_code(self):
        return self.assessment.client.format_finding_code(self)
    
    @property
    def bugtracking_link(self):
        return os.getenv('JIRA_SERVER') + "/browse/" + self.bugtracking if self.bugtracking else None

    @classmethod
    def build_from_template(cls, template: FindingTemplate, assessment: Assessment):
        lang = assessment.lang
        client = assessment.client
        translation: FindingTemplateTranslation = None
        for t in template.translations:
            translation = t
            if t.lang == lang:
                break
        
        new_finding = Finding(
            name=template.name,
            type=template.type,

            tech_risk=template.tech_risk,
            business_risk=template.business_risk,
            exploitability=template.exploitability,
            dissemination=template.dissemination,
            solution_complexity=template.solution_complexity,

            owisam_category=template.owisam_category,

            template=template,

            title=translation.title,
            definition=translation.definition,
            references=translation.references,
            description=translation.description,

            assessment=assessment,

            cvss_v3_vector=template.cvss_v3_vector,
            cvss_v3_score=template.cvss_v3_score,

            client_finding_id=client.generate_finding_counter(),
        )

        for requirement in template.web_requirements:
            FindingWebRequirement(finding=new_finding, asvs_req=requirement.asvs_req)
        for requirement in template.mobile_requirements:
            FindingMobileRequirement(finding=new_finding, masvs_req=requirement.masvs_req)
        for ref in template.wstg_refs:
            FindingWebTest(finding=new_finding, wstg_ref=ref.wstg_ref)
        for ref in template.mstg_refs:
            FindingMobileTest(finding=new_finding, mstg_ref=ref.mstg_ref)
        for ref in template.cwe_refs:
            FindingCWE(finding=new_finding, cwe_ref=ref.cwe_ref)

        return new_finding

    def update_one_to_manies(self, form: FlaskForm):
        # CWE
        data_cwe = {k: v for k, v in dict(form.data).items() if k in FindingCWE.__dict__}
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
                FindingCWE(finding=self, cwe_ref=ref)
        # ASVS
        data_asvs = {k: v for k, v in dict(form.data).items() if k in FindingWebRequirement.__dict__}
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
                FindingWebRequirement(finding=self, asvs_req=asvs)
        # MASVS
        data_masvs = {k: v for k, v in dict(form.data).items() if k in FindingMobileRequirement.__dict__}
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
                FindingMobileRequirement(finding=self, masvs_req=masvs)
        # WSTG
        data_wstg = {k: v for k, v in dict(form.data).items() if k in FindingWebTest.__dict__}
        if data_wstg:
            data_wstg = data_wstg['wstg_ref']
            # Delete current relation
            for requirement in self.wstg_refs:
                if not requirement.wstg_ref in data_wstg:
                    requirement.delete()
                else:
                    data_wstg.remove(requirement.wstg_ref)
            # Create new requirements
            for wstg in data_wstg:
                FindingWebTest(finding=self, wstg_ref=wstg)
        # MSTG
        data_mstg = {k: v for k, v in dict(form.data).items() if k in FindingMobileTest.__dict__}
        if data_mstg:
            data_mstg = data_mstg['mstg_ref']
            # Delete current relation
            for requirement in self.mstg_refs:
                if not requirement.mstg_ref in data_mstg:
                    requirement.delete()
                else:
                    data_mstg.remove(requirement.mstg_ref)
            # Create new requirements
            for mstg in data_mstg:
                FindingMobileTest(finding=self, mstg_ref=mstg)

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
        for requirement in self.wstg_refs:
            wstg_refs.append(WSTG(requirement.wstg_ref))
        data['wstg_ref'] = wstg_refs
        # MSTG
        mstg_refs = []
        for requirement in self.mstg_refs:
            mstg_refs.append(MSTG(requirement.mstg_ref))
        data['mstg_ref'] = mstg_refs

        return data

    def get_requirements_string(self):
        if self.web_requirements:
            return ", ".join([ref.asvs_req.code for ref in self.web_requirements])
        elif self.mobile_requirements:
            return ", ".join([ref.masvs_req.code for ref in self.mobile_requirements])
        else:
            return None

    def get_testing_refs(self):
        if self.wstg_refs:
            return ", ".join([ref.wstg_ref.code for ref in self.wstg_refs])
        elif self.mstg_refs:
            return ", ".join([ref.mstg_ref.code for ref in self.mstg_refs])
        else:
            return None

    def get_cwe_refs(self):
        if self.cwe_refs:
            return ", ".join([ref.cwe_ref.code for ref in self.cwe_refs])
        else:
            return None

    cwe_refs = db.relationship('FindingCWE', back_populates='finding')
    web_requirements = db.relationship('FindingWebRequirement', back_populates='finding')
    mobile_requirements = db.relationship('FindingMobileRequirement', back_populates='finding')
    wstg_refs = db.relationship('FindingWebTest', back_populates='finding')
    mstg_refs = db.relationship('FindingMobileTest', back_populates='finding')


class FindingWebRequirement(Base, db.Model):
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey('finding.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )    
    asvs_req = db.Column(Enum(ASVS), primary_key=True)
    finding = db.relationship('Finding', back_populates='web_requirements')


class FindingMobileRequirement(Base, db.Model):
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey('finding.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )    
    masvs_req = db.Column(Enum(MASVS), primary_key=True)
    finding = db.relationship('Finding', back_populates='mobile_requirements')


class FindingWebTest(Base, db.Model):
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey('finding.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    wstg_ref = db.Column(Enum(WSTG), primary_key=True)
    finding = db.relationship('Finding', back_populates='wstg_refs')


class FindingMobileTest(Base, db.Model):
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey('finding.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    mstg_ref = db.Column(Enum(MSTG), primary_key=True)
    finding = db.relationship('Finding', back_populates='mstg_refs')


class FindingCWE(Base, db.Model):
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey('finding.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
    cwe_ref = db.Column(Enum(CWE), primary_key=True)
    finding = db.relationship('Finding', back_populates='cwe_refs')


class Active(Base, db.Model):
    __table_args__ = (db.UniqueConstraint('assessment_id', 'name'),)
    __serialization__ = [
        AttributeConfiguration(name='name', csv_sequence=1, **supported_serialization),
        AttributeConfiguration(name='uris', **supported_serialization),
    ]

    id = db.Column(db.Integer, primary_key=True)

    assessment_id = db.Column(
        db.Integer,
        db.ForeignKey('assessment.id', onupdate='CASCADE', ondelete='CASCADE'),
        nullable=False
    )
    assessment = db.relationship(Assessment, uselist=False)

    name = db.Column(db.String(128))

    active_resources = db.relationship('AffectedResource', back_populates='active')

    @property
    def uris(self):
        for resource in self.active_resources:
            yield resource.uri


class AffectedResource(Base, db.Model):
    __table_args__ = (db.UniqueConstraint('active_id', 'route'),)
    __serialization__ = [
        AttributeConfiguration(name='uri', csv_sequence=1, **supported_serialization),
    ]

    id = db.Column(db.Integer, primary_key=True)

    active_id = db.Column(
        db.Integer,
        db.ForeignKey('active.id', onupdate='CASCADE', ondelete='CASCADE'),
        nullable=False
    )
    active = db.relationship(Active, uselist=False, back_populates='active_resources')

    route = db.Column(db.String(256))

    findings = db.relationship('Finding', secondary=finding_affected_resource)

    @property
    def uri(self):
        return "{}{}".format(self.active.name, self.route or '')

    def delete_last_reference(self):
        if len(self.findings) == 1:
            if len(self.active.active_resources) == 1 and self.active.active_resources[0] is self:
                self.active.delete()
            else:
                self.delete()
