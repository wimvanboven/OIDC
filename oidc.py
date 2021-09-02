from urllib.parse import urlencode
import requests
import json
import base64
import rsa
import time
import random
import string
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class JWT:
    def __init__(self, representation):
        self.representation = representation
        (h, b, s) = str.split(self.representation, '.')
        self.body = base64.b64decode(b + '===')
        self.header = base64.b64decode(h + '===')
        self.signature = base64.urlsafe_b64decode(s + '===')

    def get_claim(self, name):
        return json.loads(self.body)[name]

    def verify(self, key):
        rsa.PublicKey.load_pkcs1(key)
        try:
            (h, b, s) = str.split(self.representation, '.')
            rsa.verify('.'.join(h,b), rsa.PublicKey )
        except:
            return False
        return True


class OIDC:
    class GrantType:
        REFRESH_TOKEN = "refresh_token"
        TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
        PASSWORD = "password"
        AUTH_CODE = "authorization_code"
        CIBA = "urn:openid:params:grant-type:ciba"
        CLIENT_CREDENTIALS='client_credentials'

    def __init__(self, well_known_url="", client_ID="", client_secret=""):
        self.client_ID = client_ID
        self.client_secret = client_secret
        self.authorization_endpoint = ""
        self.token_endpoint = ""
        self.assertion = ""
        self.ciba_endpoint = ""

        if len(well_known_url):
            self.configure(well_known_url)

    def _is_secret(self):
        return bool(len(self.client_secret))

    def _is_signed_jwt(self):
        return bool(len(self.assertion))

    def configure(self, well_known_url):
        req = requests.get(well_known_url)
        res = req.text
        wk = json.loads(req.text)
        self.authorization_endpoint = wk["authorization_endpoint"]
        self.token_endpoint = wk["token_endpoint"]
        
        # check for CIBA support
        try: 
            self.ciba_endpoint = wk["backchannel_authentication_endpoint"]
        except:
            self.ciba_endpoint  = ""

        return self

    def grant_code(self, code, redirect_uri):
        data = {
            'grant_type': OIDC.GrantType.AUTH_CODE,
            'client_id': self.client_ID,
            'code': code,
            'redirect_uri': redirect_uri
        }

        if self._is_secret():
            data['client_secret'] = self.client_secret

        req = requests.post(url=self.token_endpoint, data=data)
        res = req.text
        self._tokens = res
        return self

    def grant_password(self, username, password, scope=""):
        data = {
            'grant_type': OIDC.GrantType.PASSWORD,
            'client_id': self.client_ID,
            'username': username,
            'password': password,
            'scope': "openid"
        }

        if self._is_secret():
            data["client_secret"] = self.client_secret

        if len(scope):
            data["scope"] = scope

        req = requests.post(self.token_endpoint, data=data)
        self._tokens = req.text
        return self

    def id_token(self):
        t = JWT(json.loads(self._tokens)["id_token"])
        return t

    def access_token(self):
        t = JWT(json.loads(self._tokens)["access_token"])
        return t

    def refresh_token(self):
        t = JWT(json.loads(self._tokens)["refresh_token"])
        return t

    def auth_code_link(self, redirect_uri, scope="", state="", query_params=None):
        # TODO: add PKCE for public client
        data = {
            'response_type': 'code',
            'client_id': self.client_ID,
            'redirect_uri': redirect_uri,
            'scope': "openid"
        }

        if len(scope):
            data['scope'] = scope

        if len(state):
            data['state'] = state

        url = self.authorization_endpoint + "?" + \
            (urlencode({**data, **query_params}))
        return url

    def grant_token_exchange(self, access_token: JWT, scope="", audience=''):
        # exchange token based on existing internal keycloak token
        data = {
            "client_id": self.client_ID,
            'grant_type': OIDC.GrantType.TOKEN_EXCHANGE,
            'requested_token_type' : 'urn:ietf:params:oauth:token-type:refresh_token',
            "subject_token": access_token.representation,
            'scope' : scope
        }
        if len(audience):
            data['audience'] = audience
        if self._is_secret():
            data["client_secret"] = self.client_secret

        if self._is_signed_jwt():
            data["client_assertion_type"] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            data["client_assertion"] = self.assertion
        
        if len(scope):
            data['scope'] = scope

        req = requests.post(url=self.token_endpoint, data=data)
        print(req.text)

        self._tokens = req.text
        return self

    def grant_refresh_token(self, refresh_token: JWT):
        data = {
            "client_id": self.client_ID,
            'grant_type': OIDC.GrantType.REFRESH_TOKEN,
            "refresh_token" : refresh_token.representation
        }
        if self._is_secret():
            data["client_secret"] = self.client_secret

        if self._is_signed_jwt():
            data["client_assertion_type"] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            data["client_assertion"] = self.assertion

        req = requests.post(url=self.token_endpoint, data=data)
        #print(req.request.body)
        #print(req.text)

        self._tokens = req.text
        return self

    def grant_naked_token_exchange(self, subject="", scope=""):
        # exchange token based on existing internal keycloak token
        data = {
            "client_id": self.client_ID,
            'grant_type': OIDC.GrantType.TOKEN_EXCHANGE,
            "requested_subject" : subject
        }
        if self._is_secret():
            data["client_secret"] = self.client_secret

        if self._is_signed_jwt():
            data["client_assertion_type"] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            data["client_assertion"] = self.assertion
        
        if len(scope):
            data['scope'] = scope

        req = requests.post(url=self.token_endpoint, data=data)
        print(req.request.body)
        print(req.text)

        self._tokens = req.text
        return self


    def make_assertion(self, certificate, key, lifetime=60):
        _alg = "RS256"

        with open(key, "rb") as privatefile:
            privkey = rsa.PrivateKey.load_pkcs1(privatefile.read())

        with open(certificate, "rb") as certfile:
            cert = x509.load_pem_x509_certificate(certfile.read(), default_backend())

        fingerprint = cert.fingerprint(hashes.SHA1())
        base64_fingerprint = base64.urlsafe_b64encode(fingerprint).decode('utf-8')

        # JWT is a three part stucture, 1st part are headers and include algorithm, the thumbprint and the type
        headers = dict(alg = _alg, typ = "JWT", x5t = base64_fingerprint)
        now = int(time.time())

        # second part is the issuer, subject, the audience, the token id (random string to prevent replay), expiration and lifetime
        payload = dict(
            iss=self.client_ID,
            sub=self.client_ID,
            aud=self.token_endpoint,
            jti= "".join(random.choices(string.digits, k=32)),
            iat=now,
            exp=now + lifetime
        )

        headers = base64.urlsafe_b64encode(json.dumps(headers).encode('utf-8')).decode('utf-8').replace('=', '')
        body = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').replace('=', '')
        # third part is the signature
        sig = rsa.sign((headers+"."+body).encode('utf-8'), privkey, 'SHA-256')
        sig = base64.urlsafe_b64encode(sig).decode("utf-8").replace('=','')

        # all are then joined by '.'
        self.assertion = ".".join([headers, body, sig])
        return self

    def grant_ciba(self, username, binding_message):
        data = {
            "client_id": self.client_ID,
            'grant_type': OIDC.GrantType.CIBA,
            'login_hint' : username,
            'binding_message' : binding_message,
            'scope' : 'openid'
            
        }
        if self._is_secret():
            data["client_secret"] = self.client_secret
       
        response = requests.post(self.ciba_endpoint, data=data)
        self.ciba_auth_req_id = json.loads(response.text)['auth_req_id']
        return self

    def ciba_poll(self, interval=1):
        data = {
            "client_id": self.client_ID,
            'grant_type': OIDC.GrantType.CIBA,
            'auth_req_id' : self.ciba_auth_req_id
            
        }
        if self._is_secret():
            data["client_secret"] = self.client_secret

        for t in range(5):
            response = requests.post(self.token_endpoint, data=data)
            print(response.text)
            if response.status_code == 200 and 'access_token' in response.text:
                self._tokens = response.text
                return self
            time.sleep(interval)
        return False

    def grant_client_credentials(self, scope='openid'):
        data = {
            "client_id": self.client_ID,
            'grant_type': OIDC.GrantType.CLIENT_CREDENTIALS,
            'scope' : scope
            
        }
        if self._is_secret():
            data["client_secret"] = self.client_secret

        if self._is_signed_jwt():
            data["client_assertion_type"] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            data["client_assertion"] = self.assertion
        
        r = requests.post(self.token_endpoint, data=data)
        #print(r.text)
        self._tokens = r.text
        return self


        
               


