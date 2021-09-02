from flask.helpers import make_response
from werkzeug.datastructures import Authorization
from oidc import OIDC, JWT
from flask import Flask, redirect, request, url_for
import requests
import threading
import time


app = Flask(__name__)
oidc = None

@app.route("/ciba")
def ciba():
    oidc.grant_ciba('wim', '123').ciba_poll(interval=2)
    return oidc.access_token().body,200


@app.route("/")
def hello():
    content = "hello world, welcome to application A</br>"
    content += "<a href='login'>login</a> <br /><a href='ciba'>ciba</a> <br />"

    return content

@app.route("/login")
def login():
    url = oidc.auth_code_link("http://localhost:5000/callback", scope="openid crmid", query_params={"ui_locales": "en"})
    return redirect(url, code=302)

@app.route("/silent")
def silent():
    url = oidc.auth_code_link("http://localhost:5000/callback", scope="openid crmid", query_params={"ui_locales": "en", "prompt" : 'none'})
    return redirect(url, code=302)


@app.route("/callback")
def callback():
    code = request.args.get('code')
    t = oidc.grant_code(code, "http://localhost:5000/callback").id_token()
    return t.body

@app.route("/auth", methods=['POST'])
def auth():
    # method serves as an authentication device. 
    token = request.headers['Authorization'][7:]
    # spawn the authentication device mock
    t = threading.Thread(target=authentication_result_mock, args=(token,) )
    t.start()
    # default keycloak CIBA SPI expects 201 empty response as an ack on the ciba request
    response = make_response('', 201)
    return response

def authentication_result_mock(token):
    # call back with the authentication result (always succeed)
    time.sleep(5)
    headers = {
        'Authorization' : 'Bearer ' + token,
        'Content-Type' : 'application/json'
    }
    json = {
        'status' : 'SUCCEED'
    }
    response = requests.post(oidc.ciba_endpoint + '/callback', json=json, headers=headers)
    print(response.text)
    return

if __name__ == '__main__':
    oidc = OIDC("http://localhost:8080/auth/realms/customers/.well-known/openid-configuration",
            "sso", "4f4df5f1-c851-4b34-9252-d2d57c5fa49c")
    app.run(debug=True, port=5000, host='0.0.0.0')
