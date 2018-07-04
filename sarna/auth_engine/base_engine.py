from abc import ABCMeta, abstractmethod


class BaseEngine(metaclass=ABCMeta):

    @abstractmethod
    def authenticate(self, username, password, otp=None):
        pass
