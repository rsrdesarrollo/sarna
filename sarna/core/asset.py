from os import path

from flask_assets import Environment

from sarna.core.config import config


def init_app(app):
    assets = Environment(app)
    assets.from_yaml(path.join(
        config.PROJECT_PATH,
        'resources',
        'assets.yaml'
    ))


__all__ = ["init_app"]
