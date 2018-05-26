from flask import redirect, request


def redirect_referer(default_url):
    if not default_url:
        AttributeError('need default url')

    referer = request.headers.get('referer')
    if referer.startswith(request.host_url):
        return redirect(referer)
    else:
        return redirect(default_url)
