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
    Contain the application factory
    It tells Python that the app directory should be treated as a package
    Route and blueprint configuration
"""

import os, sys, platform

from flask import Flask, redirect

def create_app(test_config=None):
    """create and configure the app"""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        # change it for your enviroment
        SECRET_KEY='github_dev',
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route('/')
    def root():
        return redirect('/login')

    @app.route('/data')
    @app.route('/data/')
    def data():
        return redirect('/data/select')


    from . import auth
    app.register_blueprint(auth.bp)
    
    from . import data
    app.register_blueprint(data.bp)

    return app

