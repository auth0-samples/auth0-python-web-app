"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
from os import environ as env, path
import json

from auth0.v3.authentication import GetToken
from auth0.v3.authentication import Users
from dotenv import load_dotenv
from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
from flask import session
import requests

import constants

load_dotenv(path.join(path.dirname(__file__), ".env"))
API_AUDIENCE = env[constants.API_ID]
AUTH0_CALLBACK_URL = env[constants.AUTH0_CALLBACK_URL]
AUTH0_CLIENT_ID = env[constants.AUTH0_CLIENT_ID]
AUTH0_CLIENT_SECRET = env[constants.AUTH0_CLIENT_SECRET]
AUTH0_DOMAIN = env[constants.AUTH0_DOMAIN]

APP = Flask(__name__, static_url_path='')
APP.secret_key = constants.SECRET_KEY
APP.debug = True


def requires_auth(f):
    """Determines if the access token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

# Controllers API
@APP.route('/')
def home():
    return render_template('home.html', env=env)


@APP.route('/dashboard', methods=['GET', 'POST'])
@requires_auth
def dashboard():
    if request.method == 'POST':
        json_header = {
            constants.CONTENT_TYPE_KEY: constants.APP_JSON_KEY,
            'authorization': 'bearer {access_token}'.format(access_token=session['access_token'])
        }
        api_response = requests.get('http://localhost:3001/secured/ping',
                                    headers=json_header)
        return render_template('dashboard.html',
                                   user=session[constants.PROFILE_KEY], apires=api_response.text)
    return render_template('dashboard.html',
                           user=session[constants.PROFILE_KEY])


@APP.route('/public/<path:filename>')
def static_files(filename):
    return send_from_directory('./public', filename)


@APP.route('/callback')
def callback_handling():
    code = request.args.get(constants.CODE_KEY)
    get_token = GetToken(AUTH0_DOMAIN)
    auth0_users = Users(AUTH0_DOMAIN)
    token = get_token.authorization_code(AUTH0_CLIENT_ID,
                                         AUTH0_CLIENT_SECRET, code, AUTH0_CALLBACK_URL)
    user_info = auth0_users.userinfo(token['access_token'])
    session['access_token'] = token['access_token']
    session[constants.PROFILE_KEY] = json.loads(user_info)
    return redirect('/dashboard')

if __name__ == "__main__":
    APP.run(host='0.0.0.0', port=env.get('PORT', 3000))
