from datetime import datetime

from sqlathanor import AttributeConfiguration
from unidecode import unidecode

from sarna.core.config import config
from sarna.model.base import Base, db, supported_serialization

__all__ = ['Client', 'Template', 'client_management', 'client_audit']

client_management = db.Table(
    'client_management',
    db.Column(
        'managed_client_id',
        db.Integer,
        db.ForeignKey('client.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    ),
    db.Column(
        'manager_id',
        db.Integer,
        db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
)
client_audit = db.Table(
    'client_audit',
    db.Column(
        'audited_client_id',
        db.Integer,
        db.ForeignKey('client.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    ),
    db.Column(
        'auditor_id',
        db.Integer,
        db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True
    )
)

client_template = db.Table(
    'client_template',
    db.Column(
        'client_id',
        db.Integer,
        db.ForeignKey('client.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    ),
    db.Column(
        'template_id',
        db.Integer,
        db.ForeignKey('template.id', onupdate='CASCADE', ondelete='CASCADE'),
        primary_key=True
    )
)


class Client(Base, db.Model):
    __serialization__ = [
        AttributeConfiguration(name='id', csv_sequence=1, **supported_serialization),
        AttributeConfiguration(name='short_name', **supported_serialization),
        AttributeConfiguration(name='long_name', **supported_serialization),
    ]

    id = db.Column(db.Integer, primary_key=True)
    short_name = db.Column(db.String(64), nullable=False)
    long_name = db.Column(db.String(128), nullable=False)

    assessments = db.relationship('Assessment', back_populates='client')
    templates = db.relationship('Template', secondary=client_template, back_populates='clients')

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"), nullable=False)
    creator = db.relationship("User", back_populates="created_clients", uselist=False)

    managers = db.relationship('User', secondary=client_management, back_populates='managed_clients')
    auditors = db.relationship('User', secondary=client_audit, back_populates='audited_clients')

    finding_counter = db.Column(db.Integer, default=0, nullable=False)

    def generate_finding_counter(self) -> int:
        tx_commit = False
        while not tx_commit:
            self.finding_counter = Client.finding_counter + 1
            db.session.add(self)
            try:
                db.session.commit()
                tx_commit = True
            except Exception as ex:
                pass

        return self.finding_counter

    def format_finding_code(self, finding) -> str:
        client_name_prefix = unidecode(self.short_name).replace(" ", "_").upper()

        return f"{client_name_prefix}_{finding.assessment.creation_date:%Y%m%d}_{finding.client_finding_id:06d}"


class Template(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(32), unique=True, nullable=False)
    description = db.Column(db.String(128), nullable=False)
    last_modified = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    file = db.Column(db.String(128), nullable=False)

    clients = db.relationship('Client', secondary=client_template, back_populates='templates')

    @staticmethod
    def template_path():
        return config.TEMPLATES_PATH

    """
    Multi-Select Field helper methods
    """

    @classmethod
    def get_choices(cls, *args):
        return list((u, u.name) for u in Template.query.filter(*args).order_by(Template.name))

    @classmethod
    def coerce(cls, item):
        if isinstance(item, Template):
            return item
        return cls.query.filter_by(name=item).first()

    def __str__(self):
        return self.name
