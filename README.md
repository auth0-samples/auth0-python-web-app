# Auth0 Python Flask Quickstart

A minimal Flask application demonstrating Auth0 authentication with cookie-based session persistence.

## Prerequisites

- Python 3.9+
- [uv](https://docs.astral.sh/uv/) package manager
- An [Auth0](https://auth0.com) account

## Setup

1. Install dependencies:

```bash
uv sync
```

2. Fill in your Auth0 credentials in the `.env` file:

```
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_SECRET=<openssl rand -hex 32>
APP_BASE_URL=http://localhost:5000
```

3. In your [Auth0 Dashboard](https://manage.auth0.com), configure your application:
   - **Allowed Callback URLs**: `http://localhost:5000/callback`
   - **Allowed Logout URLs**: `http://localhost:5000`

4. Run the app:

```bash
uv run python server.py
```

## What it does

- `/` — Shows login/signup links, or user profile if authenticated
- `/login` — Redirects to Auth0 Universal Login
- `/callback` — Handles the OAuth2 callback
- `/logout` — Clears session and redirects to Auth0 logout
