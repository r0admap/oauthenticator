"""
Custom Authenticator to use dingtalk OAuth with JupyterHub
"""


import json
import os
import base64
import urllib
import urllib3

from tornado.auth import OAuth2Mixin
from tornado import gen, web
from tornado import escape

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator

DINGTALK_AUTHORIZE_URL =  "https://oapi.dingtalk.com/connect/qrconnect"
DINGTALK_ACCESS_TOKEN_URL = "https://oapi.dingtalk.com/sns/gettoken"
DINGTALK_USER_CODE_URL = "https://oapi.dingtalk.com/sns/get_persistent_code"
DINGTALK_SNS_TOKEN_URL = "https://oapi.dingtalk.com/sns/get_sns_token"
DINGTALK_USERDATA_URL = "https://oapi.dingtalk.com/sns/getuserinfo"

class DingTalkMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = DINGTALK_ACCESS_TOKEN_URL
    _OAUTH_AUTHORIZE_URL = DINGTALK_AUTHORIZE_URL


class DingTalkLoginHandler(OAuthLoginHandler, DingTalkMixin):
    def authorize_redirect(self, *args, **kwargs):
        """Add idp, skin to redirect params"""
        extra_params = kwargs.setdefault('extra_params', {})
        if self.authenticator.client_id:
            extra_params["appid"] = self.authenticator.client_id
            extra_params["scope"]='snsapi_login' 
        return super().authorize_redirect(*args, **kwargs)

class DingTalkOAuthenticator(OAuthenticator):

    login_service = Unicode(
        "阿里钉钉扫码登录",
        config=True
    )

    login_handler = DingTalkLoginHandler
#    scope = Unicode(
#        "snsapi_login",
#        config=True
#    )

    userdata_url = Unicode(
        DINGTALK_USERDATA_URL,
        config=True,
        help="Userdata url to get user data login information"
    )

    access_token_url = Unicode(
        DINGTALK_ACCESS_TOKEN_URL,
        config=True,
        help="Access token endpoint URL"
    )

    sns_token_url = Unicode(
        DINGTALK_SNS_TOKEN_URL,
        config=True,
        help="SNS token endpoint URL"
    )

    user_code_url = Unicode(
        DINGTALK_USER_CODE_URL,
        config=True,
        help="User persistent_code endpoint URL"
    )

    username_key = Unicode(
        'openid',
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )
    userdata_params = Dict(
        # {maskedMobile,nick,openid,unionid,dingId}
	{},
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        'GET',
        config=True,
        help="Userdata method to get user data login information"
    )

    user_code_method = Unicode(
        'POST',
        config=True,
        help="User persistent_code method"
    )

    sns_token_method = Unicode(
        'POST',
        config=True,
        help="SNS token method"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
#        scope = 'snsapi_login'

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Content-Type": "application/json"
        }


        params = dict(
            appid=self.client_id,
            appsecret=self.client_secret,
        )

        if self.access_token_url:
            url = self.access_token_url
        else:
            raise ValueError("Please set the ACCESS_TOKEN_URL environment variable")



        url = url_concat(DINGTALK_ACCESS_TOKEN_URL, params)

        self.log.info(url)

        req = HTTPRequest(url,
                          headers=headers
			  )


        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.info(resp_json)

        access_token = resp_json['access_token']

        self.log.info("Access token acquired"+access_token)

#########


        if self.user_code_url:
            url = self.user_code_url
        else:
            raise ValueError("Please set the DINGTALK_USER_CODE_URL environment variable")

        params = dict(access_token=access_token)
        url = url_concat(DINGTALK_USER_CODE_URL, params)
        params = {'tmp_auth_code': code, 'temp': code}
        self.log.info(url)
        self.log.info(params)

        body_encode = escape.json_encode(params)
        self.log.info(body_encode)

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body=escape.to_unicode(body_encode)
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.info(resp_json)

        openid = resp_json['openid']
        persistent_code = resp_json['persistent_code']
        unionid = resp_json['unionid']
        self.log.info(openid)

#        scope = (resp_json.get('scope', '')).split(' ')


#SNS_TOKEN############

    if self.sns_token_url:
            url = self.sns_token_url
        else:
            raise ValueError("Please set the DINGTALK_SNS_TOKEN_URL variable")

        params = dict(access_token=access_token)
        url = url_concat(DINGTALK_SNS_TOKEN_URL, params)
        params = {'openid': openid, 'persisitent_code': persisitent_code}
        self.log.info(url)
        self.log.info(params)

        body_encode = escape.json_encode(params)
        self.log.info(body_encode)

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body=escape.to_unicode(body_encode)
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.info(resp_json)

        expires_in = resp_json['expires_in']
        sns_token = resp_json['sns_token']
        self.log.info(sns_token)

################




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
#        resp = yield http_client.fetch(req)
#        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

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
