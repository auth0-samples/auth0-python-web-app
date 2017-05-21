"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
from urllib.parse import urlparse
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


@APP.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           user=session[constants.PROFILE_KEY], env=env)

@APP.route('/logout')
def logout():
    session.clear()
    parsed_base_url = urlparse(AUTH0_CALLBACK_URL)
    base_url = parsed_base_url.scheme + '://' + parsed_base_url.netloc
    return redirect('https://%s/v2/logout?returnTo=%s&client_id=%s' % (AUTH0_DOMAIN, base_url, AUTH0_CLIENT_ID))

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
    session[constants.PROFILE_KEY] = json.loads(user_info)
    return redirect('/dashboard')

if __name__ == "__main__":
    APP.run(host='0.0.0.0', port=env.get('PORT', 3000))
