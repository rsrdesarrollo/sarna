from sarna.auth_engine.exceptions import InvalidAuthEngineException
from sarna.auxiliary.patterns import Singleton


class AuthController(metaclass=Singleton):
    _auth_chain = []

    @classmethod
    def add_auth_engine(cls, engine):
        cls._auth_chain.append(engine)

    @classmethod
    def authenticate(cls, username, password, otp=None):
        for engine in cls._auth_chain:
            try:
                user = engine.authenticate(username, password, otp)
                user.login()
            except InvalidAuthEngineException:
                continue
