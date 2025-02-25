# Auth0 Access Token For Connection Integration Guide
This guide demonstrates how to integrate Auth0's federated access token functionality in a Flask application. This approach allows your application to authenticate users once with Auth0 and then access multiple third-party services using tokens that Auth0 manages on your behalf.

## Prerequisites
- Python 3.7+
- Auth0 account with a configured application
- Environment variables for Auth0 credentials

## Step 1: Clone the Sample Application
```bash
git clone https://github.com/auth0-samples/auth0-python-web-app.git
cd auth0-python-web-app
```

## Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

## Step 4: Using Auth0-Python SDK for Client Intialization 

```python
from auth0.authentication import GetToken
# Initialize the GetToken object with your Auth0 domain and client credentials
auth_client = GetToken('your-domain.us.auth0.com', 'your-client-id', client_secret='your-client-secret')
```

## Step 5: Modify the Login Route
Replace the standard Authlib login route with a custom implementation that supports federated access:
```python
@app.route("/login")
def login():
    """Manually build the Auth0 authorization URL for redirection."""
    # Clear any existing session
    session.clear()
    # Generate a secure state parameter for OAuth flow
    session['oauth_state'] = secrets.token_urlsafe(16)
    # Get configuration values
    auth0_domain = env.get("AUTH0_DOMAIN")
    client_id = env.get("AUTH0_CLIENT_ID")
    client_secret = env.get("AUTH0_CLIENT_SECRET")
    # Generate the callback URL
    redirect_uri = url_for("callback", _external=True)
    # Construct the Auth0 authorization URL
    auth_url = (
        f"https://{auth0_domain}/authorize?"
        + urlencode({
            "client_id": client_id,
            "client_secret": client_secret,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "access_type": "offline",
            "prompt": "consent",
            "scope": "offline_access openid profile email",
            "grant_type": "authorization_code",
            "state": session['oauth_state'],
        })
    )
    return redirect(auth_url)
```

## Step 6: Update Callback Handler
Update the callback handler to work with the custom login route:
```python
@app.route("/callback")
def callback():
    # Verify state parameter
    if session.get('oauth_state') != request.args.get('state'):
        return "State verification failed", 400
    # Get the authorization code
    code = request.args.get("code")
    # Exchange code for tokens
    token_url = f"https://{env.get('AUTH0_DOMAIN')}/oauth/token"
    token_payload = {
        "grant_type": "authorization_code",
        "client_id": env.get("AUTH0_CLIENT_ID"),
        "client_secret": env.get("AUTH0_CLIENT_SECRET"),
        "code": code,
        "redirect_uri": url_for("callback", _external=True)
    }
    # Get tokens from Auth0
    token_response = requests.post(token_url, json=token_payload).json()
    # Store tokens in session (including refresh_token)
    session["tokens"] = {
        "access_token": token_response.get("access_token"),
        "refresh_token": token_response.get("refresh_token"),
        "id_token": token_response.get("id_token")
    }

    # Get user info
    user_info_url = f"https://{env.get('AUTH0_DOMAIN')}/userinfo"
    user_info_headers = {"Authorization": f"Bearer {token_response.get('access_token')}"}
    user_info = requests.get(user_info_url, headers=user_info_headers).json()
    # Store user info in session
    session["user"] = user_info
    return redirect("/")
```

## Step 7: Implement Federated Token Route
Add a new route for handling federated connections:
```python
@app.route("/federated/<connection>")
def federated_login(connection):
    """Handles federated login flow."""
    try:
        # Store connection name
        connection_name = connection
        # Attempt to get refresh token from session
        refresh_token = session.get("tokens", {}).get("refresh_token")
        # Call SDK federated connection function
        federated_token_response = auth_client.access_token_for_connection(
            subject_token=refresh_token,
            subject_token_type="urn:ietf:params:oauth:token-type:refresh_token",
            requested_token_type="http://auth0.com/oauth/token-type/federated-connection-access-token",
            connection=connection_name,
            grant_type="urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
        )
        # Check for successful token retrieval
        if not federated_token_response:
            return "Failed to retrieve federated access token", 500
        # Extract the access token
        access_token = federated_token_response["access_token"]
        # Call the third-party API using the federated token
        api_response = call_third_party_api(access_token)
        # Handle API response
        if not api_response:
            return "API returned an empty response. Check authentication and scopes.", 500
        # Prepare and return the response to the user
        return render_template(
            "federated_result.html",
            connection=connection_name,
            data=api_response
        )
    except Exception as e:
        return f"An error occurred: {str(e)}", 500
```

## Step 8: Implement Third-Party API Call Function
Create a helper function to call the third-party API:
```python
def call_third_party_api(access_token):
    """Generic function to call a third-party API with the federated access token."""
    # Set up headers with the access token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    # Make the API request
    response = requests.get(
        "https://api.third-party-service.com/endpoint",
        headers=headers
    )
    # Check for successful response
    if response.status_code == 200:
        return response.json()
    else:
        print(f"API request failed with status code: {response.status_code}")
        return None
```

## Step 9: Run the Application
```bash
python server.py
```

## Key Concepts
1. **Federated Connection**: An Auth0 feature that allows your application to obtain access tokens for third-party services through Auth0.
2. **Token Exchange**: The process of exchanging a refresh token for a service-specific access token.
3. **Offline Access**: Requesting permission to refresh tokens even when the user is not present.
4. **Connections**: Auth0's term for different identity providers or authentication methods (google-oauth2, github, etc.).

