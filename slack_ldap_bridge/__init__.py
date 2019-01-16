"""
A small flask application to add a user's slack ID to CSH LDAP
"""

import os
from flask import Flask, request, redirect, session
from flask_pyoidc.flask_pyoidc import OIDCAuthentication
import requests
import csh_ldap

APP = Flask(__name__)

if os.path.exists(os.path.join(os.getcwd(), "config.py")):
    APP.config.from_pyfile(os.path.join(os.getcwd(), "config.py"))
else:
    APP.config.from_pyfile(os.path.join(os.getcwd(), "config.env.py"))

_AUTH = OIDCAuthentication(APP,
                           issuer=APP.config['OIDC_ISSUER'],
                           client_registration_info=APP.config['OIDC_CLIENT_CONFIG'])

_LDAP = csh_ldap.CSHLDAP(APP.config['LDAP_DN'], APP.config['LDAP_SECRET'])

_ACCESS_URI = 'https://slack.com/api/oauth.access' \
       + '?redirect_uri=%s&client_id=%s&client_secret=%s&code=%s'


@APP.route('/')
@_AUTH.oidc_auth
def _handle():
    resp = requests.get(_ACCESS_URI %
                        (APP.config['REDIRECT_URI'], APP.config['SLACK_CLIENT_ID'],
                         APP.config['SLACK_SECRET'], request.args.get('code')))
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)
    member.slackID = resp.json()['user']['id']
    return redirect(APP.config['RETURN_URI'], code=302)
