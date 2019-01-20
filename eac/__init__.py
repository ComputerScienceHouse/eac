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

APP.secret_key = APP.config['SECRET_KEY']

_AUTH = OIDCAuthentication(APP,
                           issuer=APP.config['OIDC_ISSUER'],
                           client_registration_info=APP.config['OIDC_CLIENT_CONFIG'])

_LDAP = csh_ldap.CSHLDAP(APP.config['LDAP_DN'], APP.config['LDAP_SECRET'])

_ACCESS_URI = 'https://slack.com/api/oauth.access' \
       + '?redirect_uri=%s&client_id=%s&client_secret=%s&code=%s'


@APP.route('/slack', methods=['GET'])
@_AUTH.oidc_auth
def _link_slack():
    """ Links Slack into LDAP via slackUID """
    resp = requests.get(_ACCESS_URI %
                        (APP.config['REDIRECT_URI'], APP.config['SLACK_CLIENT_ID'],
                         APP.config['SLACK_SECRET'], request.args.get('code')))
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)
    print(resp.json()) # DEBUG
    member.slackUID = resp.json()['user']['id']
    return redirect(APP.config['RETURN_URI'], code=302)


@APP.route('/slack', methods=['DELETE'])
@_AUTH.oidc_auth
def _revoke_slack():
    """ Revokes Slack by clearing slackUID """
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)
    member.slackUID = None
