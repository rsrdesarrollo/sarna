from werkzeug.routing import RequestRedirect, MethodNotAllowed, NotFound

from sarna import app

_url_adapter = app.url_map.bind('localhost')


def parse_url(url, method='GET'):
    try:
        match = _url_adapter.match(url, method=method)
    except RequestRedirect as e:
        # recursively match redirects
        return parse_url(e.new_url, method)
    except (MethodNotAllowed, NotFound):
        # no match
        return None

    try:
        # return the view function and arguments
        return app.view_functions[match[0]], match[1]
    except KeyError:
        # no view is associated with the endpoint
        return None


__all__ = ['parse_url']
