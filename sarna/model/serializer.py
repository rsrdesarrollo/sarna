import json

from pony.orm.core import Entity

from sarna import Choice


def _json_serializer(value):
    if isinstance(value, Choice):
        return value.value
    else:
        return str(value)


def _to_dict_spanning_tree(obj: Entity, skip_attrs, visited):
    attrs = obj.__class__._get_attrs_(with_collections=True, with_lazy=True)
    result = {}
    for attr in attrs:

        if attr.name in skip_attrs:
            continue

        value = attr.__get__(obj)
        if attr.is_collection:
            ref = value
            value = []
            for item in sorted(ref):
                if item not in visited:
                    visited.add(item)
                    value.append(_to_dict_spanning_tree(item, skip_attrs, visited))
                    visited.remove(item)
        elif attr.is_relation and value is not None:
            if value in visited:
                continue

            ref = value
            visited.add(ref)
            value = _to_dict_spanning_tree(value, skip_attrs, visited)
            visited.remove(ref)

        if value:
            result[attr.name] = value
    return result


def to_dict(obj: Entity, skip_attrs={}):
    return _to_dict_spanning_tree(obj, skip_attrs, {obj})


def to_json(obj: Entity, skip_attrs={}, pretty=False):
    data = to_dict(obj, skip_attrs)

    if pretty:
        return json.dumps(data, sort_keys=True, indent=4, default=_json_serializer)
    else:
        return json.dump(data, default=_json_serializer)
