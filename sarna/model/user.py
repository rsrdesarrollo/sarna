from datetime import datetime

import pyotp
from sqlalchemy import event, insert
from sqlalchemy.orm.interfaces import EXT_CONTINUE, EXT_STOP
from flask_login import login_user
from werkzeug.security import generate_password_hash

from sarna.core.auth_engine.exceptions import AuthException
from sarna.core.roles import valid_auditors, valid_managers, valid_admins
from sarna.model.assessment import auditor_approval, assessment_audit, Assessment
from sarna.model.base import Base, db
from sarna.model.client import client_management, client_audit, Client
from sarna.model.enums import UserType, AuthSource, UserAction, AssessmentStatus
from sarna.model.finding_template import FindingTemplate
from sarna.model.sql_types import Enum

__all__ = ['User', 'UserAudit']


class User(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True)

    user_type = db.Column(Enum(UserType), default=UserType.auditor, nullable=False)

    source = db.Column(Enum(AuthSource), default=AuthSource.database, nullable=False)
    passwd = db.Column(db.String(128))

    creation_date = db.Column(db.DateTime, default=lambda: datetime.now(), nullable=False)
    last_access = db.Column(db.DateTime)
    login_try = db.Column(db.SmallInteger, default=0, nullable=False)

    is_locked = db.Column(db.Boolean(), default=False, nullable=False)
    otp_enabled = db.Column(db.Boolean(), default=False, nullable=False)
    otp_seed = db.Column(db.String(16))

    created_clients = db.relationship(Client, back_populates="creator")
    created_assessments = db.relationship(Assessment, back_populates="creator")

    managed_clients = db.relationship(Client, secondary=client_management, back_populates='managers')
    audited_clients = db.relationship(Client, secondary=client_audit, back_populates='auditors')
    audited_assessments = db.relationship(Assessment, secondary=assessment_audit, back_populates='auditors')
    approvals = db.relationship(Assessment, secondary=auditor_approval, back_populates='approvals')

    created_findings = db.relationship(FindingTemplate, back_populates='creator')

    def __str__(self):
        return self.username

    """
    Properties
    """

    @property
    def is_admin(self):
        return self.user_type in valid_admins

    @property
    def is_manager(self):
        return self.user_type in valid_managers

    @property
    def is_auditor(self):
        return self.user_type in valid_auditors

    @property
    def name(self):
        return self.username

    @property
    def is_readonly(self):
        return not self.user_type in valid_auditors

    """
    Assessment access methods
    """

    def get_user_assessments(self):
        if self.is_admin:
            return Assessment.query.all()
        elif self.is_auditor:
            return Assessment.query.filter(
                (Assessment.creator == self) |
                (Assessment.client_id.in_(map(lambda x: x.id, self.managed_clients))) |
                (Assessment.client_id.in_(map(lambda x: x.id, self.audited_clients))) |
                (Assessment.auditors.any(User.id == self.id))
            ).all()
        else:
            return Assessment.query.filter(
                Assessment.status.in_([AssessmentStatus.Open, AssessmentStatus.Closed])
            )


    """
    Check permissions methods
    """

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
        elif isinstance(obj, Assessment):
            return self.manages(obj.client)

        return False

    def audits(self, obj):
        if self.owns(obj) or self.manages(obj):
            return True

        if isinstance(obj, Client):
            return obj in self.audited_clients
        elif isinstance(obj, Assessment):
            return self.audits(obj.client) or obj in self.audited_assessments

        return False

    """
    Authentication
    """

    def login(self):
        self.last_access = datetime.now()
        self.login_try = 0
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

    def set_database_passwd(self, passwd):
        self.passwd = generate_password_hash(passwd)
        db.session.commit()

    def change_password(self, password, new_password, otp=None):
        try:
            self.source.engine.change_password(self, password, new_password, otp)
        except AuthException:
            return False
        return True

    def check_password(self, password):
        try:
            self.source.engine.verify_passwd(self, password)
        except AuthException:
            return False
        return True

    def generate_otp(self):
        if self.otp_enabled:
            raise ValueError('otp already set')

        self.otp_seed = pyotp.random_base32()
        db.session.commit()
        return pyotp.totp.TOTP(self.otp_seed).provisioning_uri(self.username, issuer_name="SARNA")

    def enable_otp(self, otp, password):
        if self.otp_enabled:
            raise ValueError('otp already set')

        otp_ok = self.check_otp(otp)

        if otp_ok and self.check_password(password):
            self.otp_enabled = True
            db.session.commit()

        return self.otp_enabled

    def disable_otp(self, otp, password):
        if not self.otp_enabled:
            raise ValueError('otp already disabled')

        otp_ok = self.check_otp(otp)

        if otp_ok and self.check_password(password):
            self.otp_enabled = False
            db.session.commit()

        return not self.otp_enabled

    def confirm_otp(self, otp):
        if not self.otp_enabled:
            raise ValueError('otp not set')

        return self.check_otp(otp)

    def check_otp(self, otp):
        totp = pyotp.TOTP(self.otp_seed)
        return totp.verify(otp)

    """
    Multi-Select Field helper methods
    """

    @classmethod
    def get_choices(cls, *args):
        return list((u, u.name) for u in User.query.filter(*args).order_by(User.username))

    @classmethod
    def coerce(cls, item):
        if isinstance(item, User):
            return item
        return cls.query.filter_by(username=item).first()


class UserAudit(Base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.Integer, nullable=False)
    source = db.Column(db.Integer, nullable=False)
    creation_date = db.Column(db.String(50))
    is_locked = db.Column(db.Boolean(), default=False, nullable=False)
    otp_enabled = db.Column(db.Boolean(), default=False, nullable=False)
    last_access = db.Column(db.String(50))

    @classmethod
    def build(cls, action: UserAction, instance: User):
        return UserAudit(
            user_id=instance.id,
            action=action.value,
            username=instance.username,
            user_type=instance.user_type.value,
            source=instance.source.value if instance.source else AuthSource.database.value,
            creation_date=instance.creation_date,
            is_locked=instance.is_locked if instance.is_locked is not None else False,
            otp_enabled=instance.otp_enabled if instance.otp_enabled is not None else False,
            last_access=instance.last_access
        )


@event.listens_for(User, 'before_insert', retval=True)
def audit_before_insert(mapper, connection, target):
    return create_audit(connection, target, UserAction.init)


@event.listens_for(User, 'after_insert', retval=True)
def audit_after_insert(mapper, connection, target):
    return create_audit(connection, target, UserAction.create)


@event.listens_for(User, 'before_update', retval=True)
def audit_update(mapper, connection, target):
    return create_audit(connection, target, UserAction.update)


@event.listens_for(User, 'before_delete', retval=True)
def audit_delete(mapper, connection, target):
    return create_audit(connection, target, UserAction.delete)


def create_audit(connection, target, action):
    try:
        reg = UserAudit.build(action=action, instance=target)
        ins = UserAudit.__table__.insert().values(
            user_id=reg.user_id,
            action=action.value,
            username=reg.username,
            user_type=reg.user_type,
            source=reg.source,
            creation_date=reg.creation_date,
            is_locked=reg.is_locked,
            otp_enabled=reg.otp_enabled,
            last_access=reg.last_access
        )
        connection.execute(ins)
    except Exception as e:
        #TODO: logger
        raise e
    return EXT_CONTINUE
