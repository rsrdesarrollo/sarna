from abc import ABCMeta, abstractmethod

from sqlalchemy.exc import IntegrityError

from sarna.core.auth_engine.exceptions import *
from sarna.model import db, User
from sarna.model.enums import AuthSource


class BaseEngine(metaclass=ABCMeta):

    @staticmethod
    @abstractmethod
    def auth_source() -> AuthSource:
        pass

    def __init__(self, max_try=3):
        self.max_try = max_try

        if self.auth_source().engine is not None:
            raise ConfigException('Authentication engine already set for {}'.format(self.auth_source().name))

        self.auth_source().engine = self

    @staticmethod
    @abstractmethod
    def get_user(username) -> User:
        pass

    @staticmethod
    @abstractmethod
    def change_password(user: User, password, new_password, otp=None):
        pass

    @staticmethod
    @abstractmethod
    def verify_passwd(user: User, password):
        pass

    @staticmethod
    def verify_otp(user: User, otp):
        if user.otp_enabled and not otp:
            raise NeedsOTPException()

        if user.otp_enabled and not user.confirm_otp(otp):
            raise InvalidCredentialsException()

    def authenticate(self, username, password, otp=None):
        user = self.get_user(username)

        try:
            if user.source != self.auth_source():
                raise InvalidAuthEngineException()

            user.login_try += 1
            if user.login_try > self.max_try:
                user.is_locked = True

            if user.is_locked:
                raise LockedUserException()

            self.verify_passwd(user, password)
            self.verify_otp(user, otp)

            db.session.add(user)
            db.session.commit()

            return user
        except IntegrityError:
            raise AuthEngineFailedException('Error when creating user')
        finally:
            db.session.rollback()
