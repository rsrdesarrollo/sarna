import os

from sarna.core.config import config
from sarna.model.base import Base, db

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


class Client(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    short_name = db.Column(db.String(64), nullable=False)
    long_name = db.Column(db.String(128), nullable=False)

    assessments = db.relationship('Assessment', back_populates='client')
    templates = db.relationship('Template', backref='client')

    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="CASCADE", ondelete="CASCADE"), nullable=False)
    creator = db.relationship("User", back_populates="created_clients", uselist=False)

    managers = db.relationship('User', secondary=client_management, back_populates='managed_clients')
    auditors = db.relationship('User', secondary=client_audit, back_populates='audited_clients')

    def template_path(self):
        return os.path.join(config.TEMPLATES_PATH, str(self.id))


class Template(Base, db.Model):
    name = db.Column(db.String(32), primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id', onupdate="CASCADE", ondelete="CASCADE"), primary_key=True)

    description = db.Column(db.String(128))
    file = db.Column(db.String(128), nullable=False)
