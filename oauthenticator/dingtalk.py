"""
Custom Authenticator to use dingtalk OAuth with JupyterHub
"""


import json
import os
import base64
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator

DINGTALK_AUTHORIZE_URL =  "https://oapi.dingtalk.com/connect/qrconnect"
DINGTALK_ACCESS_TOKEN_URL = "https://oapi.dingtalk.com/sns/gettoken"
DINGTALK_USER_CODE_URL = "https://oapi.dingtalk.com/sns/get_persistent_code"
DINGTALK_SNS_TOKEN_URL = "https://oapi.dingtalk.com/sns/get_sns_token"
DINGTALK_USER_URL = "https://oapi.dingtalk.com/sns/getuserinfo"

class DingTalkMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = DINGTALK_ACCESS_TOKEN_URL
    _OAUTH_AUTHORIZE_URL = DINGTALK_AUTHORIZE_URL


class DingTalkLoginHandler(OAuthLoginHandler, DingTalkMixin):
    pass


class DingTalkOAuthenticator(OAuthenticator):

    login_service = Unicode(
        "DingTalkOAuth2",
        config=True
    )

    login_handler = DingTalkLoginHandler

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )
    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', ''),
        config=True,
        help="Access token endpoint URL"
    )

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )
    userdata_params = Dict(
        os.environ.get('OAUTH2_USERDATA_PARAMS', {}),
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        scope = (resp_json.get('scope', '')).split(' ')

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return

        return {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }


class LocalDingTalkOAuthenticator(LocalAuthenticator, DingTalkOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
