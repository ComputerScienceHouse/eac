""" A flask application to handle connecting external accounts into CSH LDAP """

import os
import subprocess
from flask import Flask, request, redirect, session, render_template, send_from_directory
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

_SLACK_AUTH_URI = 'https://slack.com/oauth/authorize' \
        + '?scope=identity.basic&client_id=%s&state=%s' \
        + '&redirect_uri=https://eac.csh.rit.edu/slack/return'
_SLACK_ACCESS_URI = 'https://slack.com/api/oauth.access' \
        + '?client_id=%s&client_secret=%s&code=%s'
_GITHUB_AUTH_URI = 'https://github.com/login/oauth/authorize' \
        + '?client_id=%s&state=%s'
_GITHUB_TOKEN_URI = 'https://github.com/login/oauth/access_token' \
        + '?client_id=%s&client_secret=%s&code=%s'

_ORG_HEADER = {'Authorization' : 'token ' + APP.config['ORG_TOKEN'],
               'Accept' : 'application/vnd.github.v3+json'}

@APP.route('/static/<path:path>', methods=['GET'])
def _send_static(path):
    return send_from_directory('static', path)

@APP.route('/')
def _index():
    commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).strip().decode('utf-8')
    member = _LDAP.get_member('mom', uid=True)
    return render_template('home.html', commit_hash=commit_hash,
                           slack=member.slackuid, github=member.github)

@APP.route('/slack', methods=['GET'])
@_AUTH.oidc_auth
def _auth_slack():
    return redirect(_SLACK_AUTH_URI %
                    (APP.config['SLACK_CLIENT_ID'], APP.config['SLACK_STATE']))


@APP.route('/slack/return', methods=['GET'])
@_AUTH.oidc_auth
def _link_slack():
    """ Links Slack into LDAP via slackUID """
    resp = requests.get(_SLACK_ACCESS_URI %
                        (APP.config['SLACK_CLIENT_ID'],
                         APP.config['SLACK_SECRET'], request.args.get('code')))
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)
    print(resp.text)
    member.slackUID = resp.json()['user']['id']
    return render_template('landing_page.html')


@APP.route('/slack', methods=['DELETE'])
@_AUTH.oidc_auth
def _revoke_slack():
    """ Revokes Slack by clearing slackUID """
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)
    member.slackUID = None


@APP.route('/github', methods=['GET'])
@_AUTH.oidc_auth
def _auth_github():
    # Redirect to github for authorisation
    return redirect(_GITHUB_AUTH_URI %
                    (APP.config['GITHUB_CLIENT_ID'], APP.config['LINK_STATE']))

@APP.route('/github/return', methods=['GET'])
@_AUTH.oidc_auth
def _github_landing(): # pylint: disable=inconsistent-return-statements

    # Determine if we have a valid reason to do things
    state = request.args.get('state')
    if state != APP.config['LINK_STATE']:
        return "Invalid state", 400

    # Get token from github
    resp = requests.post(_GITHUB_TOKEN_URI %
                         (APP.config['GITHUB_CLIENT_ID'], APP.config['GITHUB_SECRET'],
                          request.args.get('code')),
                          headers={'Accept':'application/json'})
    print(resp.text)
    token = resp.json()['access_token']
    header = {'Authorization' : 'token ' + token,
              'Accept' : 'application/vnd.github.v3+json'}

    user_resp = requests.get('https://api.github.com/user', headers=header)
    print(user_resp.text)
    github = user_resp.json()['login']

    # Pull member from LDAP
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)

    _link_github(github, member)
    return render_template('landing_page.html')


def _link_github(github, member):
    """
    Puts a member's github into LDAP and adds them to the org.
    :param github: the user's github username
    :param member: the member's LDAP object
    """
    resp = requests.put("https://api.github.com/orgs/ComputerScienceHouse/memberships/" + github, headers=_ORG_HEADER)
    print(resp.json()) # Debug
    member.github = github


@APP.route('/github', methods=['DELETE'])
@_AUTH.oidc_auth
def _revoke_github():
    """ Clear's a member's github in LDAP and removes them from the org. """
    uid = str(session["userinfo"].get("preferred_username", ""))
    member = _LDAP.get_member(uid, uid=True)
    requests.delete("https://api.github.com/orgs/ComputerScienceHouse/members/" + member.github, headers=_ORG_HEADER)
    member.github = None
