from werkzeug.security import check_password_hash

from sarna.core.auth_engine.base_engine import BaseEngine
from sarna.core.auth_engine.exceptions import *
from sarna.model import User
from sarna.model.enums import AuthSource


class DataBaseEngine(BaseEngine):

    @staticmethod
    def auth_source():
        return AuthSource.database

    @staticmethod
    def get_user(username):
        user = User.query.filter_by(username=username).first()

        if not user:
            raise UserNotFoundException()

        return user

    @staticmethod
    def verify_passwd(user: User, password):
        if not check_password_hash(user.passwd, password):
            raise InvalidCredentialsException()

    @staticmethod
    def change_password(user: User, password, new_password, otp=None):
        DataBaseEngine.verify_otp(user, otp)
        DataBaseEngine.verify_passwd(user, password)

        user.set_database_passwd(password)
