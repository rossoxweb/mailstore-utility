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
    This Controller retrieve data from MailStore SPE API
    in asynchronous way and display it in the dashboard
"""


from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)
from werkzeug.exceptions import abort

from app.mailstore import MailStoreAPI

from app.auth import login_required, logout

import json


bp = Blueprint('data', __name__,  url_prefix='/data')


@bp.route('/select')
@login_required
def get_data():
    """render dashboard template"""
    return render_template('data/data.html', user=session["user_id"])

@bp.route('/userMailKeep', methods=('GET', 'POST'))
@login_required
def change_user_password():
    """change MailStore user's password
    :return: render jinja2 template
    """
    user = session["user_id"]
    istance = session["istance"]
    userpwd = MailStoreAPI(istance, user)
    if request.method == 'POST':
        pwdconfirm = request.form['password-confirm']
        userpwd.set_user_password(pwdconfirm)
        session.clear()
        return redirect(url_for('auth.login'))
    return render_template('data/usermk.html', user=session["user_id"] )


@bp.route('/changeprofilepassword/<profileId>', methods=('GET', 'POST'))
@login_required
def changepassword(profileId):
    """change password of the given profile ID, when the button "#change-profile-pwd-btn" from data.html is clicked
    :param profileId: selected profile ID
    :return: render jinja2 template
    """
    user = session["user_id"]
    istance = session["istance"]
    api = MailStoreAPI(istance, user)

    if request.method == 'POST':
        pwdconfirm = request.form['password-confirm']
        result = api.update_profile(profileId, pwdconfirm)
        if result == 'La password è errata':
            flash(result)
        else:
            return render_template('operationsuccess.html', user=session["user_id"])
    return render_template('data/userprofile.html', user=session["user_id"])


@bp.route('/getstorage', methods=('GET', 'POST'))
@login_required
def getspace():
    """Method is invoked from data.html ajax, to display storage usage
    :return: json of MailStore user's storage usage
    """
    user = session["user_id"]
    istance = session["istance"]
    api = MailStoreAPI(istance, user)
    # retrieve storage usage
    data_usage = api.get_user_statistics()
    return jsonify(data_usage), 202


@bp.route('/getuserprofiles', methods=('GET', 'POST'))
@login_required
def getuserprofiles():
    """Method is invoked from data.html ajax, to display profile, the ajax function then manage 'name' and 'id' values
    :return: json of MailStore user's profile data
    """
    user = session["user_id"]
    istance = session["istance"]
    api = MailStoreAPI(istance, user)
    # retrieve existing profiles
    existing_profiles = api.get_profiles()
    return jsonify(existing_profiles), 202


@bp.route('/getprofileresult/<profileId>', methods=('GET', 'POST'))
@login_required
def getprofilesresult(profileId):
    """ Method is invoked from data.html ajax function "getStatus", which manage "result", "startTime", "completeTime" values
    :param profileId: selected profile ID
    :return: json of profile (or profiles) result of the MailStore user
    """
    user = session["user_id"]
    istance = session["istance"]
    api = MailStoreAPI(istance, user)

    # filter result of profiles by their id
    profile_result = api.profiles_status()
    for result in profile_result['result']:
        if str(result['profileId']) == profileId:
            risultato = result
            return jsonify(risultato), 202


@bp.route('/getprofilesconnector/<profileId>', methods=('GET', 'POST'))
@login_required
def getprofilesconnector(profileId):
    """Method is invoked from data.html ajax function getConnector, which check if the profile it's IMAP or not
    :param profileId: selected profile ID
    :return: profile connector
    """
    user = session["user_id"]
    istance = session["istance"]
    api = MailStoreAPI(istance, user)
    result = api.get_profile_connector(profileId)
    return jsonify(result), 202