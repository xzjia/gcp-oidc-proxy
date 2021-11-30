import os
import logging
import google.auth

from functools import wraps
from flask import request
from google.auth.transport.requests import Request as GRequest
from google.oauth2 import id_token
from requests import Session
from requests import Request

HOST_HEADER = 'Forward-Host'

_session = Session()

_whitelist = os.getenv('WHITELIST', [])
if _whitelist:
    _whitelist = [p.strip() for p in _whitelist.split(',')]

_client_id = os.getenv('CLIENT_ID')
_username = os.getenv('AUTH_USERNAME')
_password = os.getenv('AUTH_PASSWORD')


def requires_auth(f):
    """Decorator to enforce Basic authentication on requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if _is_auth_enabled():
            if not auth or not _check_auth(auth.username, auth.password):
                return ('Could not verify your access level for that URL.\n'
                        'You have to login with proper credentials.', 401,
                        {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated


@requires_auth
def handle_request(proxied_request):
    """Proxy the given request to the URL in the Forward-Host header with an
    Authorization header set using an OIDC bearer token for the Cloud
    Function's service account. If the header is not present, return a 400
    error.
    """

    host = proxied_request.headers.get(HOST_HEADER)
    if not host:
        return 'Required header {} not present'.format(HOST_HEADER), 400

    scheme = proxied_request.headers.get('X-Forwarded-Proto', 'https')
    url = '{}://{}{}'.format(scheme, host, proxied_request.path)
    headers = dict(proxied_request.headers)

    # Check path against whitelist.
    path = proxied_request.path
    if not path:
        path = '/'
    # TODO: Implement proper wildcarding for paths.
    if '*' not in _whitelist and path not in _whitelist:
        logging.warn('Rejected {} {}, not in whitelist'.format(
            proxied_request.method, url))
        return 'Requested path {} not in whitelist'.format(path), 403

    _oidc_token = _get_google_oidc_token(_client_id)

    # Add the Authorization header with the OIDC token.
    headers['Authorization'] = 'Bearer {}'.format(_oidc_token)

    # We don't want to forward the Host header.
    headers.pop('Host', None)
    request = Request(proxied_request.method, url,
                      headers=headers,
                      data=proxied_request.data)

    # Send the proxied request.
    prepped = request.prepare()
    logging.info('{} {}'.format(prepped.method, prepped.url))
    resp = _session.send(prepped)

    # Strip hop-by-hop headers and Content-Encoding.
    headers = _strip_hop_by_hop_headers(resp.headers)
    headers.pop('Content-Encoding', None)

    return resp.content, resp.status_code, headers.items()


def _get_google_oidc_token(client_id):
    """
    Obtain an OpenID Connect (OIDC) token from metadata server or using service
    account.
    """
    return id_token.fetch_id_token(GRequest(), client_id)


_hoppish = {
    'connection': 1,
    'keep-alive': 1,
    'proxy-authenticate': 1,
    'proxy-authorization': 1,
    'te': 1,
    'trailers': 1,
    'transfer-encoding': 1,
    'upgrade': 1,
}.__contains__


def _is_hop_by_hop(header_name):
    """Return True if 'header_name' is an HTTP/1.1 "Hop-by-Hop" header."""
    return _hoppish(header_name.lower())


def _strip_hop_by_hop_headers(headers):
    """Return a dict with HTTP/1.1 "Hop-by-Hop" headers removed."""
    return {k: v for (k, v) in headers.items() if not _is_hop_by_hop(k)}


def _check_auth(username, password):
    """Validate a username/password combination."""
    return username == _username and password == _password


def _is_auth_enabled():
    """Return True if authentication is enabled, False if not."""
    return _username is not None and _password is not None
