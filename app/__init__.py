# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################

"""
Application Initialization File:
Handles application setup, configuration, and exception handling.
"""

import os, sys, logging
from flask import Flask, render_template
from flask_session import Session
from flask_cors import CORS
from app.app_config.config import ConfService

# Extend system path to include the current directory
sys.path.append(os.path.dirname(__file__))


def page_not_found(e):
    return (
        render_template(
            "500.html",
            error_code="Page not found",
            error="Page not found.We're sorry, we couldn't find the page you requested.",
        ),
        404,
    )

def create_app():
        
    app = Flask(__name__, instance_relative_config=True)
    app.config['SECRET_KEY'] = ConfService.secret_key
    
    app.logger.setLevel(logging.INFO)
    
    # Initialize LoginManager
    from flask_login import LoginManager
    login_manager = LoginManager()
    login_manager.login_view = 'SCA.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        from model.user import User
        from model.user_service import UserService
        return User(user_id) if any(user['username'] == user_id for user in UserService.get_users()) else None    

    def handle_exception(e):
        app.logger.error("Internal Server Error: %s", str(e), exc_info=True)

        return (
            render_template(
                "500.html",
                error="Sorry, an internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
                error_code="Internal Server Error",
            ),
            500,
        )

    # Register error handlers
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(500, handle_exception)

    # Register routes
    from . import (routes)
    app.register_blueprint(routes.rp)

    # Configure session    
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_THRESHOLD"] = 50
    app.config["SESSION_PERMANENT"] = False # Controls whether sessions persist between app restarts.
    app.config['SESSION_USE_SIGNER'] = True # Ensures sessions are cryptographically signed to prevent tampering
    app.config['SESSION_KEY_PREFIX'] = 'rp-centric-session:'
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    Session(app)

    # Configure CORS
    CORS(app, supports_credentials=True, resources={r"/tester/*": {"origins": ConfService.as_url}})
    return app