import logging
import os
import re

from flask import Flask, request, jsonify
from flask_login import LoginManager
from flask_jwt_extended import jwt_required
from flask_wtf.csrf import CSRFError
from flask_mail import Mail
import i18n

from qwc_services_core.auth import auth_manager, optional_auth, get_identity
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface)
from db_auth import DBAuth


app = Flask(__name__)

app.config['JWT_COOKIE_SECURE'] = os.environ.get(
    'JWT_COOKIE_SECURE', 'False') == 'True'
app.config['JWT_COOKIE_SAMESITE'] = os.environ.get(
    'JWT_COOKIE_SAMESITE', 'Lax')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get(
    'JWT_ACCESS_TOKEN_EXPIRES', 12*3600))
app.config['SESSION_COOKIE_SECURE'] = app.config['JWT_COOKIE_SECURE']
app.config['SESSION_COOKIE_SAMESITE'] = app.config['JWT_COOKIE_SAMESITE']
app.config['WTF_CSRF_ENABLED'] = True

jwt = auth_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']

i18n.set('load_path', [os.path.join(os.path.dirname(__file__), 'translations')])
i18n.set('file_format', 'json')
SUPPORTED_LANGUAGES = ['en', 'de', 'fr']
# *Enable* WTForms built-in messages translation
# https://wtforms.readthedocs.io/en/2.3.x/i18n/
app.config['WTF_I18N_ENABLED'] = False


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
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get(
        'MAIL_DEFAULT_SENDER', 'root')
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
app.session_interface = TenantSessionInterface()


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


@app.route('/verify_login', methods=['POST'])
@optional_auth
def verify_login():
    return db_auth_handler().verify_login()


@app.route('/verify', methods=['POST'])
@optional_auth
def verify():
    return db_auth_handler().verify()


@app.route('/logout', methods=['GET', 'POST'])
@optional_auth
def logout():
    return db_auth_handler().logout(get_identity())


@app.route('/totp', methods=['POST'])
@optional_auth
def setup_totp():
    return db_auth_handler().setup_totp()


@app.route('/qrcode', methods=['GET'])
@optional_auth
def qrcode():
    return db_auth_handler().qrcode()


@app.route('/password/new', methods=['GET', 'POST'])
@optional_auth
def new_password():
    return db_auth_handler().new_password()


@app.route('/password/edit', methods=['GET', 'POST'])
@optional_auth
def edit_password():
    token = request.args.get('reset_password_token')
    return db_auth_handler().edit_password(token, get_identity())

@app.route('/unlock', methods=['GET'])
def unlock_account():
    token = request.args.get('reset_password_token')
    return db_auth_handler().unlock_account(token)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return redirect(request.url)

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
             request.accept_languages.best_match(SUPPORTED_LANGUAGES) or 'en')


if __name__ == '__main__':
    print("Starting DB Auth service...")
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)
