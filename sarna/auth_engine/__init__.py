from .auth_controller import AuthController
from .database_engine import DataBaseEngine

_controller = AuthController()
_controller.add_auth_engine(DataBaseEngine())
