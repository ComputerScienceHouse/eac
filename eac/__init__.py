""" A flask application to handle connecting external accounts into CSH LDAP """

import os
import subprocess
import random
import string
import time
import urllib.parse
import hmac
from hashlib import sha1
import base64
from typing import Any

import jwt
from requests.models import HTTPError

import flask
import werkzeug
from flask import Flask, request, redirect, session, render_template, send_from_directory, jsonify
from flask_pyoidc.flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
import csh_ldap
import requests
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

APP = Flask(__name__)

if os.path.exists(os.path.join(os.getcwd(), 'config.py')):
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
else:
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.env.py'))

sentry_sdk.init(dsn=APP.config['SENTRY_DSN'],
                integrations=[FlaskIntegration()])

APP.secret_key = APP.config['SECRET_KEY']

_CONFIG = ProviderConfiguration(
    APP.config['OIDC_ISSUER'],
    client_metadata=ClientMetadata(**APP.config['OIDC_CLIENT_CONFIG']))
_AUTH = OIDCAuthentication({'default': _CONFIG}, APP)

_LDAP = csh_ldap.CSHLDAP(APP.config['LDAP_DN'], APP.config['LDAP_SECRET'])

_SLACK_AUTH_URI = 'https://slack.com/oauth/authorize' \
        + '?scope=identity.basic' \
        + '&client_id=%s' \
        + '&state=%s' \
        + '&redirect_uri=https://eac.csh.rit.edu/slack/return'
_SLACK_ACCESS_URI = 'https://slack.com/api/oauth.access' \
        + '?client_id=%s' \
        + '&client_secret=%s' \
        + '&code=%s'

_GITHUB_AUTH_URI = 'https://github.com/login/oauth/authorize' \
        + '?client_id=%s' \
        + '&state=%s'
_GITHUB_TOKEN_URI = 'https://github.com/login/oauth/access_token' \
        + '?client_id=%s' \
        + '&client_secret=%s' \
        + '&code=%s'

_TWITCH_AUTH_URI = 'https://id.twitch.tv/oauth2/authorize' \
        + '?client_id=%s' \
        + '&redirect_uri=https://eac.csh.rit.edu/twitch/return' \
        + '&response_type=code' \
        + '&force_verify=true' \
        + '&state=%s'
_TWITCH_TOKEN_URI = 'https://id.twitch.tv/oauth2/token' \
        + '?client_id=%s' \
        + '&client_secret=%s' \
        + '&code=%s' \
        + '&grant_type=authorization_code' \
        + '&redirect_uri=https://eac.csh.rit.edu/twitch/return'

_TWITTER_REQUEST_TOKEN_URI = 'https://api.twitter.com/oauth/request_token'
_TWITTER_AUTHORIZATION_URI = 'https://api.twitter.com/oauth/authenticate'
_TWITTER_ACCESS_TOKEN_URI = 'https://api.twitter.com/oauth/access_token'
_TWITTER_ACCOUNT_INFO_URI = 'https://api.twitter.com/1.1/account/verify_credentials.json'
_TWITTER_AUTH_TOKEN_CACHE = {}


@APP.route('/static/<path:path>', methods=['GET'])
def _send_static(path: str) -> flask.wrappers.Response:
    return send_from_directory('static', path)


@APP.route('/')
@_AUTH.oidc_auth('default')
def _index() -> str:
    commit_hash = subprocess.check_output(
        ['git', 'rev-parse', '--short', 'HEAD']).strip().decode('utf-8')
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)
    services = {
        'Slack': member.slackuid,
        'GitHub': member.github,
        'Twitch': member.twitchlogin,
        'Twitter': member.twittername,
    }

    return render_template('home.html',
                           commit_hash=commit_hash,
                           uid=uid,
                           services=services)


@APP.route('/slack', methods=['GET'])
@_AUTH.oidc_auth('default')
def _auth_slack() -> werkzeug.Response:
    return redirect(_SLACK_AUTH_URI %
                    (APP.config['SLACK_CLIENT_ID'], APP.config['STATE']))


@APP.route('/slack/return', methods=['GET'])
@_AUTH.oidc_auth('default')
def _link_slack() -> tuple[str, int]:
    """ Links Slack into LDAP via slackUID """

    # Determine if we have a valid reason to do things
    state = request.args.get('state')
    if state != APP.config['STATE']:
        return 'Invalid state', 400

    resp = requests.get(
        _SLACK_ACCESS_URI %
        (APP.config['SLACK_CLIENT_ID'], APP.config['SLACK_SECRET'],
         request.args.get('code')),
        timeout=APP.config['REQUEST_TIMEOUT'],
    )
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)
    member.slackUID = resp.json()['user']['id']
    return render_template('callback.html'), 200


@APP.route('/slack', methods=['DELETE'])
@_AUTH.oidc_auth('default')
def _revoke_slack() -> werkzeug.Response:
    """ Revokes Slack by clearing slackUID """
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)
    member.slackUID = None
    return jsonify(success=True)


@APP.route('/github', methods=['GET'])
@_AUTH.oidc_auth('default')
def _auth_github() -> werkzeug.Response:
    # Redirect to github for authorisation
    return redirect(_GITHUB_AUTH_URI %
                    (APP.config['GITHUB_CLIENT_ID'], APP.config['STATE']))


@APP.route('/github/return', methods=['GET'])
@_AUTH.oidc_auth('default')
def _github_landing() -> tuple[str, int]:
    # Determine if we have a valid reason to do things
    state = request.args.get('state')
    if state != APP.config['STATE']:
        return 'Invalid state', 400

    # Get token from github
    resp = requests.post(
        _GITHUB_TOKEN_URI %
        (APP.config['GITHUB_CLIENT_ID'], APP.config['GITHUB_SECRET'],
         request.args.get('code')),
        headers={'Accept': 'application/json'},
        timeout=APP.config['REQUEST_TIMEOUT'])
    try:
        resp.raise_for_status()
    except HTTPError as e:
        print('response:', resp.json())
        raise e

    resp_json = resp.json()
    token = resp_json['access_token']
    header = {
        'Authorization': 'token ' + token,
        'Accept': 'application/vnd.github.v3+json'
    }

    user_resp = requests.get('https://api.github.com/user',
                             headers=header,
                             timeout=APP.config['REQUEST_TIMEOUT'])
    try:
        user_resp.raise_for_status()
    except HTTPError as e:
        print('response:', user_resp.json())
        raise e

    user_resp_json = user_resp.json()

    github_username = user_resp_json['login']
    github_id = user_resp_json['id']

    # Pull member from LDAP
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)

    _link_github(github_username, github_id, member)
    return render_template('callback.html'), 200


def _get_github_jwt() -> str:
    signing_key = APP.config["GITHUB_APP_PRIVATE_KEY"]

    payload = {
        'iat': int(time.time()),
        'exp': int(time.time() + 600),
        'iss': APP.config['GITHUB_APP_ID'],
    }

    encoded_jwt = jwt.encode(payload, signing_key, algorithm='RS256')

    return encoded_jwt


def _auth_github_org() -> str:
    jwt_auth = _get_github_jwt()

    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Bearer {jwt_auth}',
    }

    org_installation_resp = requests.get(
        'https://api.github.com/orgs/ComputerScienceHouse/installation',
        headers=headers,
        timeout=APP.config['REQUEST_TIMEOUT'])
    try:
        org_installation_resp.raise_for_status()
    except HTTPError as e:
        print('response:', org_installation_resp.json())
        raise e

    org_installation_json = org_installation_resp.json()
    org_installation_id = org_installation_json['id']

    org_token_resp = requests.post(
        f'https://api.github.com/app/installations/{org_installation_id}/access_tokens',
        headers=headers,
        timeout=APP.config['REQUEST_TIMEOUT'])
    try:
        org_token_resp.raise_for_status()
    except HTTPError as e:
        print('response:', org_token_resp.json())
        raise e

    org_token_json = org_token_resp.json()
    org_token = org_token_json['token']

    return org_token


def _link_github(github_username: str, github_id: str, member: Any) -> None:
    """
    Puts a member's github into LDAP and adds them to the org.
    :param github_username: the user's github username
    :param github_id: the user's github id
    :param member: the member's LDAP object
    """
    org_token = _auth_github_org()

    payload = {
        'org': 'ComputerScienceHouse',
        'invitee_id': github_id,
        'role': 'direct_member'
    }

    github_org_headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Token {org_token}',
    }

    resp = requests.post(
        'https://api.github.com/orgs/ComputerScienceHouse/invitations',
        headers=github_org_headers,
        json=payload,
        timeout=APP.config['REQUEST_TIMEOUT'])
    try:
        resp.raise_for_status()
    except HTTPError as e:
        print('response:', resp.json())
        raise e

    member.github = github_username


@APP.route('/github', methods=['DELETE'])
@_AUTH.oidc_auth('default')
def _revoke_github() -> werkzeug.Response:
    """ Clear's a member's github in LDAP and removes them from the org. """
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)

    org_token = _auth_github_org()

    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Token {org_token}',
    }

    resp = requests.delete(
        'https://api.github.com/orgs/ComputerScienceHouse/members/' +
        member.github,
        headers=headers,
        timeout=APP.config['REQUEST_TIMEOUT'],
    )

    try:
        resp.raise_for_status()
    except HTTPError as e:
        print('response:', resp.json())
        raise e

    member.github = None
    return jsonify(success=True)


@APP.route('/twitch', methods=['GET'])
@_AUTH.oidc_auth('default')
def _auth_twitch() -> werkzeug.Response:
    # Redirect to twitch for authorisation
    return redirect(_TWITCH_AUTH_URI %
                    (APP.config['TWITCH_CLIENT_ID'], APP.config['STATE']))


@APP.route('/twitch/return', methods=['GET'])
@_AUTH.oidc_auth('default')
def _twitch_landing() -> tuple[str, int]:
    # Determine if we have a valid reason to do things
    state = request.args.get('state')
    if state != APP.config['STATE']:
        return 'Invalid state', 400

    resp = requests.post(
        _TWITCH_TOKEN_URI %
        (APP.config['TWITCH_CLIENT_ID'], APP.config['TWITCH_CLIENT_SECRET'],
         request.args.get('code')),
        headers={'Accept': 'application/json'},
        timeout=APP.config['REQUEST_TIMEOUT'],
    )

    header = {
        'Authorization': 'OAuth ' + resp.json()['access_token'],
    }
    resp = requests.get(
        'https://id.twitch.tv/oauth2/validate',
        headers=header,
        timeout=APP.config['REQUEST_TIMEOUT'],
    )

    # Pull member from LDAP
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)

    member.twitchlogin = resp.json()['login']
    return render_template('callback.html'), 200


@APP.route('/twitch', methods=['DELETE'])
@_AUTH.oidc_auth('default')
def _revoke_twitch() -> werkzeug.Response:
    """ Clear's a member's twitch login in LDAP."""
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)
    member.twitchlogin = None
    return jsonify(success=True)


@APP.route('/twitter', methods=['GET'])
@_AUTH.oidc_auth('default')
def _auth_twitter() -> werkzeug.Response:
    # Make a POST request to get the request token
    oauth_nonce = ''.join([
        random.choice(string.ascii_letters + string.digits) for n in range(32)
    ])
    oauth_timestamp = int(time.time())
    oauth_parameter_string = f'oauth_callback={urllib.parse.quote("https://eac.csh.rit.edu/twitter/return", safe="")}' \
                             f'&oauth_consumer_key={APP.config["TWITTER_CONSUMER_KEY"]}' \
                             f'&oauth_nonce={oauth_nonce}' \
                             f'&oauth_signature_method=HMAC-SHA1' \
                             f'&oauth_timestamp={oauth_timestamp}' \
                             f'&oauth_version=1.0'
    oauth_signature_base_string = 'POST&' \
            + urllib.parse.quote(_TWITTER_REQUEST_TOKEN_URI, safe='') + '&' \
            + urllib.parse.quote(oauth_parameter_string, safe='')
    oauth_signing_key = f'{APP.config["TWITTER_CONSUMER_SECRET_KEY"]}&'
    oauth_signature = base64.b64encode(
        hmac.new(oauth_signing_key.encode(),
                 oauth_signature_base_string.encode(),
                 sha1).digest()).decode('UTF-8')

    oauth_header = f'OAuth oauth_callback="https://eac.csh.rit.edu/twitter/return"' \
                   f'oauth_consumer_key="{APP.config["TWITTER_CONSUMER_KEY"]}", ' \
                   f'oauth_nonce="{oauth_nonce}", ' \
                   f'oauth_signature="{urllib.parse.quote(oauth_signature, safe="")}", ' \
                   f'oauth_signature_method="HMAC-SHA1", ' \
                   f'oauth_timestamp="{oauth_timestamp}", ' \
                   f'oauth_version="1.0"'

    resp = requests.post(
        _TWITTER_REQUEST_TOKEN_URI,
        headers={
            'Accept': '*/*',
            'Authorization': oauth_header
        },
        timeout=APP.config['REQUEST_TIMEOUT'],
    )

    if resp.status_code != 200:
        print(f'Status: {resp.status_code}\nMessage: {resp.text}')
        return flask.make_response(('Error fetching request_token', 500))
    returned_params = dict(
        (key.strip(), val.strip())
        for key, val in (element.split('=')
                         for element in resp.text.split('&')))

    _TWITTER_AUTH_TOKEN_CACHE[
        returned_params['oauth_token']] = returned_params['oauth_token_secret']
    # Redirect to twitter for authorisation
    return redirect(
        f'{_TWITTER_AUTHORIZATION_URI}?oauth_token={returned_params["oauth_token"]}'
    )


@APP.route('/twitter/return', methods=['GET'])
@_AUTH.oidc_auth('default')
def _twitter_landing() -> tuple[str, int]:
    oauth_token = request.args.get('oauth_token')
    if oauth_token is None:
        return "Failed to get outh token", 400
    oauth_verifier = request.args.get('oauth_verifier')
    if oauth_verifier is None:
        return "Failed to get outh verifier", 400
    oauth_nonce = ''.join([
        random.choice(string.ascii_letters + string.digits) for n in range(32)
    ])
    oauth_timestamp = int(time.time())
    oauth_parameter_string = f'oauth_consumer_key={APP.config["TWITTER_CONSUMER_KEY"]}' \
                             f'&oauth_nonce={oauth_nonce}' \
                             f'&oauth_signature_method=HMAC-SHA1' \
                             f'&oauth_timestamp={oauth_timestamp}' \
                             f'&oauth_token={urllib.parse.quote(oauth_token, safe="")}' \
                             f'&oauth_verifier={urllib.parse.quote(oauth_verifier, safe="")}' \
                             f'&oauth_version=1.0'
    oauth_signature_base_string = 'POST&' \
            + urllib.parse.quote(_TWITTER_ACCESS_TOKEN_URI, safe='') + '&' \
            + urllib.parse.quote(oauth_parameter_string, safe='')
    oauth_signing_key = f'{APP.config["TWITTER_CONSUMER_SECRET_KEY"]}&{_TWITTER_AUTH_TOKEN_CACHE[oauth_token]}'
    oauth_signature = base64.b64encode(
        hmac.new(oauth_signing_key.encode(),
                 oauth_signature_base_string.encode(),
                 sha1).digest()).decode('UTF-8')

    oauth_header = f'OAuth oauth_consumer_key="{APP.config["TWITTER_CONSUMER_KEY"]}", ' \
                   f'oauth_nonce="{oauth_nonce}", ' \
                   f'oauth_signature="{urllib.parse.quote(oauth_signature, safe="")}", ' \
                   f'oauth_signature_method="HMAC-SHA1", ' \
                   f'oauth_timestamp="{oauth_timestamp}", ' \
                   f'oauth_token="{oauth_token}"' \
                   f'oauth_version="1.0"'
    resp = requests.post(
        _TWITTER_REQUEST_TOKEN_URI,
        data=f'oauth_verifier={oauth_verifier}',
        headers={
            'Accept': '*/*',
            'Authorization': oauth_header,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout=APP.config['REQUEST_TIMEOUT'],
    )

    returned_params = dict(
        (key.strip(), val.strip())
        for key, val in (element.split('=')
                         for element in resp.text.split('&')))
    oauth_token = returned_params['oauth_token']
    oauth_token_secret = returned_params['oauth_token_secret']
    # OK, now that we have the proper token and secret, we can get the user's information
    oauth_nonce = ''.join([
        random.choice(string.ascii_letters + string.digits) for n in range(32)
    ])
    oauth_timestamp = int(time.time())
    oauth_parameter_string = f'auth_consumer_key={APP.config["TWITTER_CONSUMER_KEY"]}' \
                             f'&oauth_nonce={oauth_nonce}' \
                             f'&oauth_signature_method=HMAC-SHA1' \
                             f'&oauth_timestamp={oauth_timestamp}' \
                             f'&oauth_token={urllib.parse.quote(oauth_token, safe="")}' \
                             f'&oauth_version=1.0'
    oauth_signature_base_string = 'POST&' \
                                  + urllib.parse.quote(_TWITTER_ACCOUNT_INFO_URI, safe='') + '&' \
                                  + urllib.parse.quote(oauth_parameter_string, safe='')
    oauth_signing_key = f"{APP.config['TWITTER_CONSUMER_SECRET_KEY']}&{oauth_token_secret}"
    oauth_signature = base64.b64encode(
        hmac.new(oauth_signing_key.encode(),
                 oauth_signature_base_string.encode(),
                 sha1).digest()).decode('UTF-8')

    oauth_header = f'OAuth oauth_consumer_key="{APP.config["TWITTER_CONSUMER_KEY"]}", ' \
                   f'oauth_nonce="{oauth_nonce}", ' \
                   f'oauth_signature="{urllib.parse.quote(oauth_signature, safe="")}", ' \
                   f'oauth_signature_method="HMAC-SHA1", ' \
                   f'oauth_timestamp="{oauth_timestamp}", ' \
                   f'oauth_token="{oauth_token}"' \
                   f'oauth_version="1.0"'
    resp = requests.get(
        _TWITTER_ACCOUNT_INFO_URI,
        headers={
            'Accept': '*/*',
            'Authorization': oauth_header
        },
        timeout=APP.config['REQUEST_TIMEOUT'],
    )
    # Pull member from LDAP
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)
    member.twittername = resp.json()[0]['screen_name']
    return render_template('callback.html'), 200


@APP.route('/twitter', methods=['DELETE'])
@_AUTH.oidc_auth('default')
def _revoke_twitter() -> werkzeug.Response:
    """ Clear's a member's twitter login in LDAP."""
    uid = str(session['userinfo'].get('preferred_username', ''))
    member = _LDAP.get_member(uid, uid=True)
    member.twittername = None
    return jsonify(success=True)


@APP.route('/logout')
@_AUTH.oidc_logout
def logout() -> werkzeug.Response:
    return redirect('/', 302)
