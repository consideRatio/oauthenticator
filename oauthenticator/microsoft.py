"""
Custom Authenticator to use Microsoft OAuth with JupyterHub.

Derived from the GitHub OAuth authenticator.
"""

import os
import json
import functools

import urllib.parse as urllib_parse

from tornado import gen, escape
from tornado.auth import OAuth2Mixin, _auth_return_future, AuthError
from tornado.web import HTTPError

from traitlets import Unicode, default

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator

# Code adjusted from tornado.auth's GoogleOAuth2Mixin
# https://github.com/tornadoweb/tornado/blob/master/tornado/auth.py#L835
class MicrosoftOAuth2Mixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    _OAUTH_USERINFO_URL = "https://graph.microsoft.com/v1.0/me"
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'microsoft_oauth'

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback):
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })

        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)

    def _on_access_token(self, future, response):
        """Callback function for the exchange to the access token."""
        if response.error:
            future.set_exception(AuthError('Microsoft auth error: %s' % str(response)))
            return

        args = escape.json_decode(response.body)
        if not future.cancelled():
            future.set_result(args)

class MicrosoftLoginHandler(OAuthLoginHandler, MicrosoftOAuth2Mixin):
    '''An OAuthLoginHandler that provides scope to MicrosoftOAuth2Mixin's
       authorize_redirect.'''
    @property
    def scope(self):
        return self.authenticator.scope


class MicrosoftOAuthHandler(OAuthCallbackHandler, MicrosoftOAuth2Mixin):
    pass


class MicrosoftOAuthenticator(OAuthenticator, MicrosoftOAuth2Mixin):

    login_handler = MicrosoftLoginHandler
    callback_handler = MicrosoftOAuthHandler

    @default('scope')
    def _scope_default(self):
        return ['offline_access', 'User.Read']

    hosted_domain = Unicode(
        os.environ.get('HOSTED_DOMAIN', ''),
        config=True,
        help="""Hosted domain used to restrict sign-in, e.g. mycollege.edu"""
    )
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Microsoft'),
        config=True,
        help="""Microsoft Apps hosted domain string, e.g. My College"""
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        handler.settings['microsoft_oauth'] = {
            'key': self.client_id,
            'secret': self.client_secret,
            'scope': self.scope,
        }
        user = yield handler.get_authenticated_user(
            redirect_uri=self.get_callback_url(handler),
            code=code)
        access_token = str(user['access_token'])

        http_client = handler.get_auth_http_client()

        response = yield http_client.fetch(
            self._OAUTH_USERINFO_URL,
            header={'Authorization': 'Bearer ' + access_token}
        )

        if not response:
            self.clear_all_cookies()
            raise HTTPError(500, 'Microsoft authentication failed')

        bodyjs = json.loads(response.body.decode())

        username = bodyjs['userPrincipalName']

        if self.hosted_domain:
            if not username.endswith('@'+self.hosted_domain) or \
                bodyjs['hd'] != self.hosted_domain:
                raise HTTPError(403,
                    "You are not signed in to your {} account.".format(
                        self.hosted_domain)
                )
            else:
                username = username.split('@')[0]

        return {
            'name': username,
            'auth_state': {
                'access_token': access_token,
                'microsoft_user': bodyjs,
            }
        }

class LocalMicrosoftOAuthenticator(LocalAuthenticator, MicrosoftOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
