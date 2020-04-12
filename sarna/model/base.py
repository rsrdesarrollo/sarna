from enum import Enum

import inflection
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Query
from sqlathanor import FlaskBaseModel, initialize_flask_sqlathanor

from sarna.core import app

db = SQLAlchemy(app, model_class=FlaskBaseModel)
db = initialize_flask_sqlathanor(db)
migrate = Migrate(app, db)

__all__ = ['db', 'Base', 'supported_serialization']


@app.after_request
def auto_commit(resp):
    db.session.commit()
    return resp


class Base(object):
    query: Query

    @declared_attr
    def __tablename__(cls):
        return inflection.underscore(cls.__name__).lower()

    def __init__(self, *args, **kwargs):
        db.Model.__init__(self, *args, **kwargs)

    def set(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)

    def to_dict(self):
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)

        return d

    def delete(self, synchronize_session=False):
        pk = {
            k.name: getattr(self, k.name)
            for k in self.__mapper__.primary_key
        }
        self.query.filter_by(**pk).delete(synchronize_session=synchronize_session)


def _serialize_enum(obj):
    if isinstance(obj, Enum):
        return str(obj)
    else:
        return obj


supported_serialization = dict(
    on_serialize=_serialize_enum,
    supports_csv=False,
    supports_json=True,
    supports_yaml=True,
    supports_dict=True
)
