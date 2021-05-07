import logging
import os
import re

from flask import Flask, request, jsonify
from flask_login import LoginManager
from flask_jwt_extended import jwt_required, jwt_optional
from flask_mail import Mail
import i18n

from qwc_services_core.jwt import jwt_manager
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface)
from db_auth import DBAuth


app = Flask(__name__)

app.config['JWT_COOKIE_SECURE'] = bool(os.environ.get(
    'JWT_COOKIE_SECURE', False))
app.config['JWT_COOKIE_SAMESITE'] = os.environ.get(
    'JWT_COOKIE_SAMESITE', 'Lax')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get(
    'JWT_ACCESS_TOKEN_EXPIRES', 12*3600))

jwt = jwt_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']

i18n.set('load_path', ['./translations'])
SUPPORTED_LANGUAGES = ['en', 'de']

# https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-v-user-logins
login = LoginManager(app)

session_query = None


def mail_config_from_env(app):
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', '127.0.0.1')
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 25))
    app.config['MAIL_USE_TLS'] = os.environ.get(
        'MAIL_USE_TLS', 'False') == 'True'
    app.config['MAIL_USE_SSL'] = os.environ.get(
        'MAIL_USE_SSL', 'False') == 'True'
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
    app.config['MAIL_DEBUG'] = int(os.environ.get('MAIL_DEBUG', app.debug))
    app.config['MAIL_MAX_EMAILS'] = os.environ.get('MAIL_MAX_EMAILS')
    app.config['MAIL_SUPPRESS_SEND'] = os.environ.get(
        'MAIL_SUPPRESS_SEND', str(app.testing)) == 'True'
    app.config['MAIL_ASCII_ATTACHMENTS'] = os.environ.get(
        'MAIL_ASCII_ATTACHMENTS', False)


mail_config_from_env(app)
mail = Mail(app)

tenant_handler = TenantHandler(app.logger)

app.wsgi_app = TenantPrefixMiddleware(app.wsgi_app)
app.session_interface = TenantSessionInterface(os.environ)


def db_auth_handler():
    """Get or create a DBAuth instance for a tenant."""
    tenant = tenant_handler.tenant()
    handler = tenant_handler.handler('dbAuth', 'handler', tenant)
    if handler is None:
        handler = tenant_handler.register_handler(
            'handler', tenant, DBAuth(tenant, mail, app))
    return handler


@login.user_loader
def load_user(id):
    return db_auth_handler().load_user(id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    return db_auth_handler().login()


@app.route('/verify', methods=['POST'])
def verify():
    return db_auth_handler().verify()


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required
def logout():
    return db_auth_handler().logout()


@app.route('/totp', methods=['POST'])
def setup_totp():
    return db_auth_handler().setup_totp()


@app.route('/qrcode', methods=['GET'])
def qrcode():
    return db_auth_handler().qrcode()


@app.route('/password/new', methods=['GET', 'POST'])
def new_password():
    return db_auth_handler().new_password()


@app.route('/password/edit', methods=['GET', 'POST'])
def edit_password():
    token = request.args.get('reset_password_token')
    return db_auth_handler().edit_password(token)


""" readyness probe endpoint """
@app.route("/ready", methods=['GET'])
def ready():
    return jsonify({"status": "OK"})


""" liveness probe endpoint """
@app.route("/healthz", methods=['GET'])
def healthz():
    return jsonify({"status": "OK"})


@app.before_request
def set_lang():
    i18n.set('locale',
             request.accept_languages.best_match(SUPPORTED_LANGUAGES))


if __name__ == '__main__':
    print("Starting DB Auth service...")
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)
