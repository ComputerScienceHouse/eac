import secrets
import os

# Flask config
IP = os.environ.get('IP', '127.0.0.1')
PORT = os.environ.get('PORT', 5000)
SERVER_NAME = os.environ.get('SERVER_NAME', 'localhost:5000')
SECRET_KEY = os.environ.get('SESSION_KEY',
                            default=''.join(secrets.token_hex(16)))

# OpenID Connect SSO config
OIDC_ISSUER = os.environ.get('OIDC_ISSUER',
                             'https://sso.csh.rit.edu/auth/realms/csh')
OIDC_CLIENT_CONFIG = {
    'client_id': os.environ.get('OIDC_CLIENT_ID', ''),
    'client_secret': os.environ.get('OIDC_CLIENT_SECRET', ''),
}

# LDAP config
LDAP_DN = os.environ.get('LDAP_DN', '')
LDAP_SECRET = os.environ.get('LDAP_SECRET', '')

# Sentry config
SENTRY_DSN = os.environ.get('SENTRY_DSN', '')

# Slack secrets
SLACK_CLIENT_ID = os.environ.get('SLACK_CLIENT_ID', '')
SLACK_SECRET = os.environ.get('SLACK_SECRET', '')

# GitHub secrets
GITHUB_CLIENT_ID = os.environ.get('GITHUB_ID', '')
GITHUB_SECRET = os.environ.get('GITHUB_SECRET', '')
ORG_TOKEN = os.environ.get('GITHUB_ORG_TOKEN', '')

# Twitch secrets
TWITCH_CLIENT_ID = os.environ.get('TWITCH_CLIENT_ID', '')
TWITCH_CLIENT_SECRET = os.environ.get('TWITCH_CLIENT_SECRET', '')

# Twitter secrets
TWITTER_CONSUMER_KEY = os.environ.get('TWITTER_OAUTH_CONSUMER_KEY', '')
TWITTER_CONSUMER_SECRET_KEY = os.environ.get(
    'TWITTER_OAUTH_CONSUMER_SECRET_KEY', '')
TWITTER_TOKEN = os.environ.get('TWITTER_OAUTH_TOKEN', '')
TWITTER_TOKEN_SECRET = os.environ.get('TWITTER_OAUTH_TOKEN_SECRET', '')
GITHUB_APP_ID = os.environ.get('GITHUB_APP_ID', '')
GITHUB_APP_SECRET = os.environ.get('GITHUB_APP_SECRET', '')


# Common secrets
STATE = os.environ.get('STATE', 'auth')

# Connection controls
REQUEST_TIMEOUT = os.environ.get("EAC_REQUEST_TIMEOUT",
                                 60)  # default to a minute timeout
