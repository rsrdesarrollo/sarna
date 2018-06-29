"""
SQLAlchemy Enum type based on Integer indices.
"""
import inspect

from aenum import Enum as PyEnum
from sqlalchemy import types


class Enum(types.TypeDecorator):
    impl = types.Integer

    def __init__(self, enum_class: PyEnum, *args, **kw):
        self.enum_class = enum_class
        types.TypeDecorator.__init__(self, *args, **kw)

    def __repr__(self):
        return "Enum({}.{})".format(
            inspect.getmodule(self.enum_class).__name__,
            self.enum_class.__name__
        )

    def process_bind_param(self, elem, _):
        if elem is None:
            return None
        return elem.value

    def process_result_value(self, value, _):
        if value is None:
            return None
        if isinstance(value, str):
            return self.enum_class[value]
        else:
            return self.enum_class(value)
