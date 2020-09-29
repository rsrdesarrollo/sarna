from typing import Collection, AnyStr

from rfc3986 import URIReference
from sqlathanor import AttributeConfiguration

from sarna.model.assessment import Assessment
from sarna.model.base import Base, db, supported_serialization
from sarna.model.enums import Score, OWASPCategory, OWISAMCategory, FindingType, FindingStatus
from sarna.model.enums.category import OWASPMobileTop10Category
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation
from sarna.model.sql_types import Enum

__all__ = ['Finding', 'Active', 'AffectedResource', 'finding_affected_resource']

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
        AttributeConfiguration(name='owasp_category', **supported_serialization),
        AttributeConfiguration(name='owasp_mobile_category', **supported_serialization),
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
        AttributeConfiguration(name='notes', **supported_serialization)
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

    owasp_category = db.Column(Enum(OWASPCategory))
    owasp_mobile_category = db.Column(Enum(OWASPMobileTop10Category))
    owisam_category = db.Column(Enum(OWISAMCategory))

    description = db.Column(db.String())
    solution = db.Column(db.String())

    tech_risk = db.Column(Enum(Score))
    business_risk = db.Column(Enum(Score))
    exploitability = db.Column(Enum(Score))
    dissemination = db.Column(Enum(Score))
    solution_complexity = db.Column(Enum(Score))

    definition = db.Column(db.String(), nullable=False)
    references = db.Column(db.String(), nullable=False)

    affected_resources = db.relationship('AffectedResource', secondary=finding_affected_resource)

    cvss_v3_vector = db.Column(db.String(128))
    cvss_v3_score = db.Column(db.Float, default=0.0, nullable=False)

    client_finding_id = db.Column(db.Integer(), nullable=False)

    notes = db.Column(db.String())

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

    @property
    def client_finding_code(self):
        return self.assessment.client.format_finding_code(self)
    
    asvs = db.Column(db.String(8))
    masvs = db.Column(db.String(8))

    @classmethod
    def build_from_template(cls, template: FindingTemplate, assessment: Assessment):
        lang = assessment.lang
        client = assessment.client
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
            owasp_mobile_category=template.owasp_mobile_category,
            owisam_category=template.owisam_category,

            template=template,

            title=translation.title,
            definition=translation.definition,
            references=translation.references,
            description=translation.description,

            assessment=assessment,

            cvss_v3_vector=template.cvss_v3_vector,
            cvss_v3_score=template.cvss_v3_score,

            client_finding_id=client.generate_finding_counter()
        )


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
