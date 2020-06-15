#!/usr/bin/python3
# -*- coding: utf-8 -*-

__author__ = "Fabio Capanni"
__copyright__ = "Copyright 2020, SEIT srl"
__credits__ = ["Fabio Capanni"]
__license__ = "AGPL"
__version__ = "1.0.0"
__maintainer__ = "Fabio Capanni"
__email__ = "fcapanni@seit.it"
__status__ = "github_dev"

"""
    Authentication controller
    Render the login page
"""

import functools
import requests
import unicodedata
import json

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=('GET', 'POST'))
def login():
    """retrieve istance, username, password from POST and try connection to the API with a curl"""
    if request.method == 'POST':

        istanza = request.form['istance']
        username = request.form['username']
        password = request.form['password']

        try:
            # curl to mailstore exposed api/authenticate
            headers = {
                'pragma': 'no-cache',
                'cache-control': 'no-cache',
                'accept': 'application/json',
                'content-type': 'application/json',
                'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7'
            }
            # payload with istance, username and password
            data = json.dumps({"username": username, "password": password})
            url = 'https://utility.domain.com/%s/api/authenticate' % (istanza)
            response = requests.post(url, headers=headers, data=data)


            # <Response [401]> there is a login problem
            if (response.status_code == 401):
                error = 'Credenziali errate'
                flash(error)
            # <Response [200]> login successfull
            elif (response.status_code == 200):
                # set session
                session.clear()
                session["user_id"] = username
                session["istance"] = istanza
                # redirect to dashboard
                return redirect(url_for('data.get_data'))
        except:
            flash("Si è verificato un problema, riprova più tardi")
    return render_template('auth/login.html')


@bp.route('/logout')
def logout():
    """clear current session"""
    url = 'https://utility.domain.com/%s/api/tokens/revoke' % (session["istance"])
    requests.post(url)
    session.clear()
    return redirect(url_for('auth.login'))


def login_required(view):
    """decorator, redirect to login page if not logged in"""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.username is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)
    return wrapped_view


@bp.before_app_request
def load_logged_in_user():
    # If a user id is stored in the session, load the user data
    user_id = session.get("user_id")

    if user_id is None:
        g.username = None
    else:
        g.username = user_id