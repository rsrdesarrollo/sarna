import inflection
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Query

from sarna.core import app

db = SQLAlchemy(app)
migrate = Migrate(app, db)

__all__ = ['db', 'Base']


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

    def delete(self, commit=True):
        db.session.delete(self, synchronize_session=False)
        if commit:
            db.session.commit()
