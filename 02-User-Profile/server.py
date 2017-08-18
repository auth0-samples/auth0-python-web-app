"""Python Flask WebApp Auth0 integration example
"""
from os import environ as env
from jose import jwt
from dotenv import load_dotenv, find_dotenv
from urllib.request import urlopen
from flask import Flask
from flask import render_template
from flask import request
from flask_oauthlib.client import OAuth

import json
import constants

load_dotenv(find_dotenv())
AUTH0_CALLBACK_URL = env[constants.AUTH0_CALLBACK_URL]
AUTH0_CLIENT_ID = env[constants.AUTH0_CLIENT_ID]
AUTH0_CLIENT_SECRET = env[constants.AUTH0_CLIENT_SECRET]
AUTH0_DOMAIN = env[constants.AUTH0_DOMAIN]
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)

APP = Flask(__name__, static_url_path='/public', static_folder='./public')
APP.secret_key = constants.SECRET_KEY
APP.debug = True
oauth = OAuth(APP)


auth0 = oauth.remote_app(
    'auth0',
    consumer_key=AUTH0_CLIENT_ID,
    consumer_secret=AUTH0_CLIENT_SECRET,
    request_token_params={
        'scope': 'openid profile',
        'audience': AUTH0_AUDIENCE
    },
    base_url='https://%s' % AUTH0_DOMAIN,
    access_token_method='POST',
    access_token_url='/oauth/token',
    authorize_url='/authorize',
)

# Controllers API
@APP.route('/')
def home():
    return render_template('home.html')


@APP.route('/callback')
def callback_handling():
    resp = auth0.authorized_response()
    if resp is None:
        raise Exception('Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        ))

    # Obtain JWT and the keys to validate the signature
    idToken = resp['id_token']
    jwks = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")

    payload = jwt.decode(idToken, jwks.read(), algorithms=['RS256'], audience=AUTH0_CLIENT_ID, issuer="https://"+AUTH0_DOMAIN+"/")

    return render_template('/dashboard.html', userinfo=payload, userinfo_pretty=json.dumps(payload, indent=4))


@APP.route('/login')
def login():
    return auth0.authorize(callback=AUTH0_CALLBACK_URL)


if __name__ == "__main__":
    APP.run(host='0.0.0.0', port=env.get('PORT', 3000))
