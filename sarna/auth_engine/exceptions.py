class AuthException(Exception):
    pass


class LockedUserException(AuthException):
    pass


class InvalidAuthEngineException(AuthException):
    pass


class UserNotFoundException(AuthException):
    pass


class NeedsOTPException(AuthException):
    pass


class InvalidCredentialsException(AuthException):
    pass
