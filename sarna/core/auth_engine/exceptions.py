class ConfigException(Exception):
    pass


class AuthException(Exception):
    pass


class AuthEngineFailedException(AuthException):
    pass


class UnauthorizedAccountException(AuthException):
    pass


class LockedUserException(UnauthorizedAccountException):
    pass


class InvalidAuthEngineException(AuthException):
    pass


class UserNotFoundException(AuthException):
    pass


class NeedsOTPException(AuthException):
    pass


class InvalidCredentialsException(AuthException):
    pass
