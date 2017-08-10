"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
from urllib.parse import urlencode
from os import environ as env
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
from flask import session
from flask import url_for
from flask_oauthlib.client import OAuth

import constants

load_dotenv(find_dotenv())
AUTH0_CALLBACK_URL = env[constants.AUTH0_CALLBACK_URL]
AUTH0_CLIENT_ID = env[constants.AUTH0_CLIENT_ID]
AUTH0_CLIENT_SECRET = env[constants.AUTH0_CLIENT_SECRET]
AUTH0_DOMAIN = env[constants.AUTH0_DOMAIN]
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)

APP = Flask(__name__, static_url_path='')
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
    if constants.PROFILE_KEY in session:
        return redirect(url_for('dashboard'))

    return render_template('home.html', env=env)


@APP.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           user=session[constants.PROFILE_KEY], env=env)

@APP.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.base_url + '/v2/logout?' + urlencode(params))

@APP.route('/public/<path:filename>')
def static_files(filename):
    return send_from_directory('./public', filename)


@APP.route('/callback')
def callback_handling():
    resp = auth0.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )

    session['access_token'] = (resp['access_token'], '')

    user_info = auth0.get('userinfo')
    session[constants.PROFILE_KEY] = user_info.data

    return redirect('/dashboard')


@APP.route('/login')
def login():
    return auth0.authorize(callback=AUTH0_CALLBACK_URL)


@auth0.tokengetter
def get_auth0_oauth_token():
    return session.get('access_token')


if __name__ == "__main__":
    APP.run(host='0.0.0.0', port=env.get('PORT', 3000))
