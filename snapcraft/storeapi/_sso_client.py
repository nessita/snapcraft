import errno
import json
import os
import socket
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from simplejson.scanner import JSONDecodeError

from ._client import Client

from . import errors
from . import constants


class HTTPServerHandler(BaseHTTPRequestHandler):
    """HTTP Server to handle callback OAuth redirects."""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(
            bytes('<html><h2>You may now close this window.</h2></html>',
                  'utf-8'))
        self.server.path = self.path

    def log_message(self, format, *args):
        # Disable logging from the HTTP Server
        return


def setup_callback_server(port, max_attempts=10):
    http_server = None
    while http_server is None and max_attempts >= 0:
        try:
            http_server = HTTPServer(('', port), HTTPServerHandler)
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                max_attempts -= 1
                port += 1
            else:
                raise
    return http_server


def get_oauth2_token(root_url):
    # A code_verifier is a high-entropy cryptographic random string using the
    # unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with
    # a minimum length of 43 characters and a maximum length of 128 characters.
    code_verifier = generate_token(50)

    http_server = setup_callback_server(port=5500)
    redirect_uri = 'http://localhost:%s/' % http_server.server_port
    client = OAuth2Session(
        client_id='pTGyHHZSIMeLlEtwPPm47j8x',  # XXX This should be a config
        scope='openid email profile',
        redirect_uri=redirect_uri,
    )

    uri, state = client.create_authorization_url(
        root_url + 'oauth/authorize',
        code_challenge=create_s256_code_challenge(code_verifier),
        code_challenge_method='S256',
        nonce=generate_token(),
    )
    print('A browser should be opened pointing to:\n\n{}\n\n'
          'Please login and close the window when finished.\n'.format(uri))
    success = webbrowser.open_new(uri)
    if success:
        http_server.handle_request()
        redirected = redirect_uri.strip('/') + http_server.path
    else:
        redirected = input('Please paste redirect URL: ').strip()
    token = client.fetch_token(
        root_url + 'oauth/token',
        authorization_response=redirected,
        code_verifier=code_verifier,
    )
    return token


class SSOClient(Client):
    """The Single Sign On server deals with authentication.
    It is used directly or indirectly by other servers.
    """

    def __init__(self, conf):
        super().__init__(
            conf,
            os.environ.get("FRANKY_API_ROOT_URL", 'http://localhost:5000/'),
        )

    def get_unbound_discharge(self, caveat_id):
        token = get_oauth2_token(self.root_url)

        data = {
            'access_token': token['access_token'],
            'id_token': token['id_token'],
            'caveat_id': caveat_id,
        }
        response = self.post(
            "macaroons/discharge",
            data=json.dumps(data),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            response_json = response.json()
        except JSONDecodeError:
            response_json = {}
        if response.ok:
            return response_json["discharge_macaroon"]
        else:
            raise errors.StoreAuthenticationError(
                "Failed to get unbound discharge", response
            )

    def refresh_unbound_discharge(self, unbound_discharge):
        data = {"discharge_macaroon": unbound_discharge}
        response = self.post(
            "macaroons/refresh",
            data=json.dumps(data),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        if response.ok:
            return response.json()["discharge_macaroon"]
        else:
            raise errors.StoreAuthenticationError(
                "Failed to refresh unbound discharge", response
            )
