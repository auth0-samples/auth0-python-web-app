"""Auth0's sample server
"""
from functools import wraps
import os

from dotenv import Dotenv
from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
from flask import session
import requests

import constants

# Load Env variables
env = None

try:
    env = Dotenv('./.env')
except IOError:
    env = os.environ

app = Flask(__name__, static_url_path='')
app.secret_key = constants.SECRET_KEY
app.debug = True


# Requires authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html', env=env)


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           user=session[constants.PROFILE_KEY])


@app.route('/public/<path:filename>')
def static_files(filename):
    return send_from_directory('./public', filename)


@app.route('/callback')
def callback_handling():
    code = request.args.get(constants.CODE_KEY)
    json_header = {constants.CONTENT_TYPE_KEY: constants.APP_JSON_KEY}
    token_url = 'https://{auth0_domain}/oauth/token'.format(
                    auth0_domain=env[constants.AUTH0_DOMAIN])
    token_payload = {
        constants.CLIENT_ID_KEY: env[constants.AUTH0_CLIENT_ID],
        constants.CLIENT_SECRET_KEY: env[constants.AUTH0_CLIENT_SECRET],
        constants.REDIRECT_URI_KEY: env[constants.AUTH0_CALLBACK_URL],
        constants.CODE_KEY: code,
        constants.GRANT_TYPE_KEY: constants.AUTHORIZATION_CODE_KEY
    }

    token_info = requests.post(token_url, json=token_payload,
                               headers=json_header).json()

    user_url = 'https://{auth0_domain}/userinfo?access_token={access_token}'\
        .format(auth0_domain=env[constants.AUTH0_DOMAIN],
                access_token=token_info[constants.ACCESS_TOKEN_KEY])

    user_info = requests.get(user_url).json()
    session[constants.PROFILE_KEY] = user_info
    return redirect('/dashboard')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 3000))
