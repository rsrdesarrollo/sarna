from sarna.auxiliary.patterns import Singleton
from sarna.core.auth_engine.exceptions import InvalidAuthEngineException, UserNotFoundException, \
    InvalidCredentialsException
from sarna.core.config import config


class AuthController(metaclass=Singleton):
    _auth_chain = []

    @classmethod
    def init_app(cls, _):
        from sarna.core.auth_engine.database_engine import DataBaseEngine
        from sarna.core.auth_engine.active_directory_engine import ActiveDirectoryEngine

        cls.add_auth_engine(DataBaseEngine())

        if config.AD_FALLBACK:
            cls.add_auth_engine(ActiveDirectoryEngine())

    @classmethod
    def add_auth_engine(cls, engine):
        cls._auth_chain.append(engine)

    @classmethod
    def authenticate(cls, username, password, otp=None):
        for engine in cls._auth_chain:
            try:
                user = engine.authenticate(username, password, otp)
                user.login()
                return
            except InvalidAuthEngineException:
                continue
            except UserNotFoundException as ex:
                if config.AD_FALLBACK:
                    continue
                else:
                    raise ex

        raise InvalidCredentialsException()
