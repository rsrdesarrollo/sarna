from sarna.config import BaseConfig
from sarna.core import app


class ConfigWrapper:
    def __getattr__(self, item):
        return app.config[item]


config: BaseConfig = ConfigWrapper()

__all__ = ['config']
