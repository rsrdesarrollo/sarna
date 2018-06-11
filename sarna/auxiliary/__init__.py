from urllib.parse import urlparse, urljoin

from flask import redirect, request, url_for


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.values.get('next'), :
        if not target:
            continue
        if is_safe_url(target):
            return target


def redirect_back(endpoint, **values):
    if not endpoint:
        AttributeError('need default uri')

    target = get_redirect_target()

    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)

    return redirect(target)
