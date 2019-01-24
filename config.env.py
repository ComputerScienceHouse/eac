import os

# Flask config
IP = os.environ.get('IP', '127.0.0.1')
PORT = os.environ.get('PORT', 5000)
SERVER_NAME = os.environ.get('SERVER_NAME', 'localhost')
SECRET_KEY = os.environ.get('SESSION_KEY', '')

# OpenID Connect SSO config
OIDC_ISSUER = os.environ.get('OIDC_ISSUER', 'https://sso.csh.rit.edu/auth/realms/csh')
OIDC_CLIENT_CONFIG = {
    'client_id': os.environ.get('OIDC_CLIENT_ID', ''),
    'client_secret': os.environ.get('OIDC_CLIENT_SECRET', ''),
}

# LDAP config
LDAP_DN = os.environ.get('LDAP_DN', '')
LDAP_SECRET = os.environ.get('LDAP_SECRET', '')

# Slack secrets
SLACK_CLIENT_ID = os.environ.get('SLACK_CLIENT_ID', '')
SLACK_SECRET = os.environ.get('SLACK_SECRET', '')
REDIRECT_URI = os.environ.get('SLACK_REDIRECT', 'http://localhost/slack:5000')
SLACK_STATE = os.environ.get('AUTH_STATE', 'auth')

RETURN_URI = os.environ.get('RETURN_URI', 'https://members.csh.rit.edu')

# GitHub secrets
LINK_STATE = os.environ.get('LINK_STATE', 'link')
GITHUB_CLIENT_ID = os.environ.get('GITHUB_ID', '')
GITHUB_SECRET = os.environ.get('GITHUB_SECRET', '')
ORG_TOKEN = os.environ.get('GITHUB_ORG_TOKEN', '')
