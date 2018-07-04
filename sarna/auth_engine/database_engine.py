from sarna.auth_engine.base_engine import BaseEngine
from sarna.auth_engine.exceptions import *
from sarna.model import User


class DataBaseEngine(BaseEngine):
    def __init__(self, max_try=5):
        self.max_try = max_try

    def authenticate(self, username, password, otp=None):
        user = User.query.filter_by(username=username).first()

        if not user:
            raise UserNotFoundException()

        user.login_try += 1
        if user.login_try > self.max_try:
            user.is_locked = True

        if user.is_locked:
            raise LockedUserException()

        if not user.check_password(password):
            raise InvalidCredentialsException()

        if user.otp_enabled and not otp:
            raise NeedsOTPException()

        if user.otp_enabled and not user.confirm_otp(otp):
            raise InvalidCredentialsException()

        user.login_try = 0
        return user
