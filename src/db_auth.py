import base64
import datetime
from io import BytesIO
import os
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, unquote

from flask import abort, flash, make_response, redirect, render_template, \
    request, Response, session, url_for, get_flashed_messages, jsonify
from flask_login import current_user, login_user, logout_user
from flask_jwt_extended import create_access_token, create_refresh_token, \
    set_access_cookies, unset_jwt_cookies, get_jwt
from flask_mail import Message
from flask_wtf import FlaskForm
import pyotp
import qrcode
import i18n
from werkzeug.security import check_password_hash

from qwc_services_core.auth import get_username
from qwc_services_core.cache import ExpiringDict
from qwc_services_core.database import DatabaseEngine
from qwc_services_core.config_models import ConfigModels
from qwc_services_core.runtime_config import RuntimeConfig

from forms import LoginForm, NewPasswordForm, EditPasswordForm, VerifyForm

ip_blacklist = ExpiringDict()

class DBAuth:
    """DBAuth class

    Provide user login and password reset with local user database.
    """

    # name of default admin user
    DEFAULT_ADMIN_USER = 'admin'

    # authentication form fields
    USERNAME = 'username'
    PASSWORD = 'password'

    # reasons requiring password change
    PASSWORD_CHANGE_REASON_REQUESTED = 'requested'
    PASSWORD_CHANGE_REASON_EXPIRED = 'expired'

    def __init__(self, tenant, mail, app):
        """Constructor

        :param str tenant: Tenant ID
        :param flask_mail.Mail mail: Application mailer
        :param App app: Flask application
        """
        self.tenant = tenant
        self.mail = mail
        self.app = app
        self.logger = app.logger

        config_handler = RuntimeConfig("dbAuth", self.logger)
        config = config_handler.tenant_config(tenant)
        self.qwc_config_schema = config.get('qwc_config_schema', 'qwc_config')

        self.login_logo = config.get('logo_image_url')
        self.login_background = config.get('background_image_url')
        self.customstylesheet = config.get('customstylesheet')
        if self.customstylesheet and not self.customstylesheet.startswith('/') and not self.customstylesheet.startswith('http'):
            self.customstylesheet = url_for('static', filename=self.customstylesheet)
        self.terms_url = config.get('terms_url')
        self.login_hint = config.get('login_hint')
        if isinstance(self.login_hint, dict):
            self.login_hint = self.login_hint.get(
                i18n.get('locale'),
                self.login_hint.get('en', '')
        )
        self.favicon = config.get('favicon')
        db_url = config.get('db_url')

        # get password constraints from config
        self.password_constraints = {
            'min_length': config.get('password_min_length', 8),
            'max_length': config.get('password_max_length', -1),
            'constraints': config.get('password_constraints', []),
            'min_constraints': config.get('password_min_constraints', 0),
            'constraints_message': config.get(
                'password_constraints_message',
                "Password does not match constraints"
            ),
            'expiry': config.get('password_expiry', -1),
            'expiry_notice': config.get('password_expiry_notice', -1),
            'update_interval': config.get('password_update_interval', -1),
            'allow_reuse': config.get('password_allow_reuse', True)
        }

        self.post_param_login = config.get('post_param_login', False)
        self.max_login_attempts = config.get('max_login_attempts', 20)
        self.totp_enabled = config.get('totp_enabled', False)
        self.totp_enabled_for_admin = config.get('totp_enabled_for_admin', False)
        self.totp_issuer_name = config.get('totp_issuer_name', 'QWC Services')
        self.ip_blacklist_duration = config.get('ip_blacklist_duration', 300)
        self.ip_blacklist_max_attempt_count = config.get('ip_blacklist_max_attempt_count', 10)
        self.force_password_change_first_login = config.get('force_password_change_first_login', False)
        self.required_restore_input = config.get('required_restore_input', ['username', 'email'])

        db_engine = DatabaseEngine()
        self.config_models = ConfigModels(
            db_engine, db_url, ['password_histories'],
            qwc_config_schema=self.qwc_config_schema
        )
        self.User = self.config_models.model('users')
        self.PasswordHistory = self.config_models.model('password_histories')

        # toggle password history according to config settings
        self.password_history_active = (
            self.password_constraints['expiry'] != -1 or
            self.password_constraints['update_interval'] != -1 or
            not self.password_constraints['allow_reuse']
        )
        if self.password_history_active and self.PasswordHistory is None:
            self.logger.warning(
                "Could not activate password history. "
                "Table 'password_histories' is missing."
            )
            self.password_history_active = False

        # get user info fields from config
        self.user_info_fields = config.get('user_info_fields', [])

    def tenant_base(self):
        """base path for tentant"""
        # Updates config['JWT_ACCESS_COOKIE_PATH'] as side effect
        prefix = self.app.session_interface.get_cookie_path(self.app)
        return prefix.rstrip('/') + '/'

    def login(self):
        """Authorize user and sign in."""
        target_url = url_path(request.args.get('url') or self.tenant_base())
        retry_target_url = url_path(request.args.get('url') or None)
        self.logger.debug("Login with target_url `%s`" % target_url)

        if self.post_param_login:
            # Pass additional parameter specified
            req = request.form
            queryvals = {}
            for key, val in req.items():
                if key not in (self.USERNAME, self.PASSWORD):
                    queryvals[key] = val
            parts = urlparse(target_url)
            target_query = dict(parse_qsl(parts.query))
            target_query.update(queryvals)
            parts = parts._replace(query=urlencode(target_query))
            target_url = urlunparse(parts) or None

        self.clear_verify_session()

        # create session for ConfigDB
        with self.db_session() as db_session, db_session.begin():

            if self.post_param_login:
                username = req.get(self.USERNAME)
                password = req.get(self.PASSWORD)
                if username:
                    self.logger.debug("Attempting to login via POST params as %s" % username)
                    user = self.find_user(db_session, name=username)
                    login_success, login_fail_reason = self.__user_is_authorized(user, password)
                    if login_success:
                        return self.__login_response(user, target_url)
                    else:
                        self.logger.info(
                            "POST_PARAM_LOGIN: %s" % login_fail_reason)
                        return redirect(url_for('login', url=retry_target_url))

            form = LoginForm(meta=wft_locales())
            form.logo = self.login_logo
            form.background = self.login_background
            form.customstylesheet = self.customstylesheet
            form.terms_url = self.terms_url
            form.favicon = self.favicon
            if form.validate_on_submit():
                self.logger.debug("Attempting to login via form as %s" % form.username.data)
                user = self.find_user(db_session, name=form.username.data)

                # NOTE: user.last_sign_in_at will be set after successful auth
                last_sign_in_at = user.last_sign_in_at if user else None

                login_success, login_fail_reason = self.__user_is_authorized(user, form.password.data)
                if login_success:

                    password_has_expired = self.password_has_expired(db_session, user)

                    force_password_change = (
                        user.force_password_change or (
                            last_sign_in_at is None and (
                                user.name == self.DEFAULT_ADMIN_USER or self.force_password_change_first_login
                            )
                        ) or password_has_expired
                    )

                    if not force_password_change:
                        if self.password_history_active:
                            # check if any password history is present
                            pw_history = self.find_latest_password_history(
                                db_session, user=user
                            )
                            if pw_history is None:
                                # add initial password history entry if missing
                                self.create_password_history(db_session, user)

                        if self.__totp_is_enabled(user):
                            session['login_uid'] = user.id
                            session['target_url'] = target_url
                            if user.totp_secret:
                                # show form for verification token
                                return self.__verify(db_session, False)
                            else:
                                # show form for TOTP setup on first sign in
                                return self.__setup_totp(db_session, False)
                        else:
                            # login successful
                            return self.__login_response(user, target_url)
                    else:
                        if password_has_expired:
                            self.logger.info(
                                "Force password change on expired password"
                            )
                            reason = self.PASSWORD_CHANGE_REASON_EXPIRED
                        else:
                            self.logger.info(
                                "Force password change on first login"
                            )
                            reason = self.PASSWORD_CHANGE_REASON_REQUESTED

                        return self.require_password_change(
                            user, reason, target_url
                        )
                else:
                    form.password.errors.append(login_fail_reason)
                    # Maybe different message when
                    # user.failed_sign_in_count >= MAX_LOGIN_ATTEMPTS
            else:
                errors = [f"{key}: {val}" for key, values in form.errors.items() for val in values]
                for error in errors:
                    flash(error)

        return render_template('login.html', form=form, i18n=i18n,
                            title=i18n.t("auth.login_page_title"),
                            login_hint=self.login_hint)

    def ensureauth(self, identity):
        """Sign out."""
        target_url = request.args.get('url', 'about:blank')
        resp = make_response(redirect(target_url))
        if identity:
            return make_response(redirect(target_url))
        else:
            return make_response(redirect(url_for('login', url=url_for('redirect', url=target_url))))

    def verify_login(self):
        """Verify user login (e.g. from basic auth header)."""
        req = request.form
        username = req.get(self.USERNAME)
        password = req.get(self.PASSWORD)
        if username:
            with self.db_session() as db_session, db_session.begin():
                user = self.find_user(db_session, name=username)
                login_success, login_fail_reason = self.__user_is_authorized(user, password)
                if login_success:
                    # access_token = create_access_token(identity=username)
                    return jsonify({"identity": username})
                else:
                    self.logger.info("verify_login: %s" % login_fail_reason)
                    abort(401)
        abort(401)

    def __totp_is_enabled(self, user):
        """ Returns whether totp is enabled for the specified user
        :param user User: The user
        """
        return self.totp_enabled or (user and user.name == self.DEFAULT_ADMIN_USER and self.totp_enabled_for_admin)

    def verify(self):
        """Handle submit of form for TOTP verification token."""
        # create session for ConfigDB
        with self.db_session() as db_session, db_session.begin():
            return self.__verify(db_session)

    def __verify(self, db_session, submit=True):
        """Show form for TOTP verification token.

        :param Session db_session: DB session
        :param bool submit: Whether form was submitted
                            (False if shown after login form)
        """
        if 'login_uid' not in session:
            self.logger.warning("TOTP not enabled or not in login process")
            return redirect(url_for('login'))

        user = self.find_user(db_session, id=session.get('login_uid', None))
        if user is None:
            self.logger.warning("user not found")
            return redirect(url_for('login'))

        if not self.__totp_is_enabled(user):
            self.logger.warning("TOTP not enabled or not in login process")
            return redirect(url_for('login'))

        form = VerifyForm(meta=wft_locales())
        form.logo = self.login_logo
        form.background = self.login_background
        form.customstylesheet = self.customstylesheet
        form.favicon = self.favicon
        if submit and form.validate_on_submit():
            if self.user_totp_is_valid(user, form.token.data):
                # TOTP verified
                target_url = session.pop('target_url', self.tenant_base())
                self.clear_verify_session()
                return self.__login_response(user, target_url)
            else:
                flash(i18n.t('auth.verfication_invalid'))
                form.token.errors.append(i18n.t('auth.verfication_invalid'))
                form.token.data = None

            if user.failed_sign_in_count >= self.max_login_attempts:
                self.logger.info("redirect to login after too many login attempts")
                return redirect(url_for('login'))

        return render_template('verify.html', form=form, i18n=i18n,
                               title=i18n.t("auth.verify_page_title"))

    def logout(self, identity):
        """Sign out."""
        target_url = url_path(request.args.get('url', self.tenant_base()))
        self.clear_verify_session()
        resp = make_response(redirect(target_url))
        if identity:
            unset_jwt_cookies(resp)
            logout_user()
        return resp

    def setup_totp(self):
        """Handle submit of form with TOTP QR Code and token confirmation."""
        # create session for ConfigDB
        with self.db_session() as db_session, db_session.begin():
            return self.__setup_totp(db_session)

    def __setup_totp(self, db_session, submit=True):
        """Show form with TOTP QR Code and token confirmation.

        :param Session db_session: DB session
        :param bool submit: Whether form was submitted
                            (False if shown after login form)
        """
        if 'login_uid' not in session:
            self.logger.warning("TOTP not enabled or not in login process")
            return redirect(url_for('login'))

        user = self.find_user(db_session, id=session.get('login_uid', None))
        if user is None:
            # user not found
            return redirect(url_for('login'))

        if not self.__totp_is_enabled(user):
            self.logger.warning("TOTP not enabled or not in login process")
            return redirect(url_for('login'))

        totp_secret = session.get('totp_secret', None)
        if totp_secret is None:
            # generate new secret
            totp_secret = pyotp.random_base32()
            # store temp secret in session
            session['totp_secret'] = totp_secret

        form = VerifyForm(meta=wft_locales())
        form.logo = self.login_logo
        form.background = self.login_background
        form.customstylesheet = self.customstylesheet
        form.favicon = self.favicon
        if submit and form.validate_on_submit():
            if pyotp.totp.TOTP(totp_secret).verify(
                form.token.data, valid_window=1
            ):
                # TOTP confirmed

                # save TOTP secret
                user.totp_secret = totp_secret
                # update last sign in timestamp and reset failed attempts
                # counter
                user.last_sign_in_at = datetime.datetime.now(datetime.UTC)
                user.failed_sign_in_count = 0

                target_url = session.pop('target_url', self.tenant_base())
                self.clear_verify_session()
                return self.__login_response(user, target_url)
            else:
                flash(i18n.t('auth.verfication_invalid'))
                form.token.errors.append(i18n.t('auth.verfication_invalid'))
                form.token.data = None

        # enable one-time loading of QR code image
        session['show_qrcode'] = True

        # show form
        resp = make_response(render_template(
            'qrcode.html', form=form, i18n=i18n,
            title=i18n.t("auth.qrcode_page_title"),
            totp_secret=totp_secret
        ))
        # do not cache in browser
        resp.headers.set(
            'Cache-Control', 'no-cache, no-store, must-revalidate'
        )
        resp.headers.set('Pragma', 'no-cache')
        resp.headers.set('Expires', '0')

        return resp

    def qrcode(self):
        """Return TOTP QR code."""
        if 'login_uid' not in session:
            self.logger.warning("TOTP not enabled or not in login process")
            abort(404)

        # check presence of show_qrcode
        # to allow one-time loading from TOTP setup form
        if 'show_qrcode' not in session:
            # not in TOTP setup form
            abort(404)
        # remove show_qrcode from session
        session.pop('show_qrcode', None)

        totp_secret = session.get('totp_secret', None)
        if totp_secret is None:
            # temp secret not set
            abort(404)

        # create session for ConfigDB
        with self.db_session() as db_session:
            # find user by ID
            user = self.find_user(db_session, id=session.get('login_uid', None))

        if user is None:
            # user not found
            abort(404)

        if not self.__totp_is_enabled(user):
            self.logger.warning("TOTP not enabled or not in login process")
            return redirect(url_for('login'))

        # generate TOTP URI
        email = user.email or user.name
        uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            email, issuer_name=self.totp_issuer_name
        )

        # generate QR code
        img = qrcode.make(uri, box_size=6, border=1)
        stream = BytesIO()
        img.save(stream, 'PNG')

        return Response(
                stream.getvalue(),
                content_type='image/png',
                headers={
                    # do not cache in browser
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                },
                status=200
            )

    def new_password(self):
        """Show form and send reset password instructions."""
        if not os.environ.get('MAIL_USERNAME'):
            form = FlaskForm()
            return render_template(
                'new_password_contact_admin.html', form=form, i18n=i18n,
                title=i18n.t("auth.new_password_page_title")
            )
        form = NewPasswordForm(meta=wft_locales())
        if 'username' not in self.required_restore_input:
            form.user.validators = []
        if 'email' not in self.required_restore_input:
            form.email.validators = []

        form.logo = self.login_logo
        form.background = self.login_background
        form.customstylesheet = self.customstylesheet
        form.favicon = self.favicon
        if form.validate_on_submit():
            # create session for ConfigDB
            with self.db_session() as db_session, db_session.begin():

                user_valid = False
                if 'username' in self.required_restore_input and 'email' in self.required_restore_input:
                    user = self.find_user(db_session, email=form.email.data)
                    user_valid = user and user.name == form.user.data
                elif 'username' in self.required_restore_input:
                    user = self.find_user(db_session, name=form.user.data)
                    user_valid = bool(user)
                elif 'email' in self.required_restore_input:
                    user = self.find_user(db_session, email=form.email.data)
                    user_valid = bool(user)

                if user_valid:
                    # generate and save reset token
                    user.reset_password_token = self.generate_token()

                    # send password reset instructions
                    try:
                        self.send_reset_passwort_instructions(user)
                    except Exception as e:
                        self.logger.error(
                            "Could not send reset password instructions to "
                            "user '%s':\n%s" % (user.email, e)
                        )
                        flash(i18n.t("auth.reset_mail_failed"))
                        return render_template(
                            'new_password.html', form=form, i18n=i18n,
                            title=i18n.t("auth.new_password_page_title"),
                            show_username='username' in self.required_restore_input,
                            show_email='email' in self.required_restore_input
                        )
                else:
                    self.logger.info("User lookup failed")

                # NOTE: show message anyway even if email not found
                flash(i18n.t("auth.reset_message"))
                return redirect(url_for('login'))

        return render_template(
            'new_password.html', form=form, i18n=i18n,
            title=i18n.t("auth.new_password_page_title"),
            show_username='username' in self.required_restore_input,
            show_email='email' in self.required_restore_input
        )

    def edit_password(self, token, identity=None):
        """Show form and reset password.

        :param token str: Password reset token
        :param identity obj: JWT identity
        """
        form = self.edit_password_form()
        form.logo = self.login_logo
        form.background = self.login_background
        form.customstylesheet = self.customstylesheet
        form.favicon = self.favicon
        if form.validate_on_submit():
            # create session for ConfigDB
            with self.db_session() as db_session, db_session.begin():

                if identity:
                    user = self.find_user(db_session, name=get_username(identity))
                else:
                    user = self.find_user(
                        db_session, reset_password_token=form.reset_password_token.data
                    )
                if user:
                    if not self.can_change_password(db_session, user):
                        # time since last password update was too short
                        flash(i18n.t("auth.edit_password_rate_limited"))
                        if not identity:
                            target_url = unquote(form.url.data) or None
                            return redirect(url_for('login', url=target_url))
                        else:
                            return render_template(
                                'edit_password.html', form=form, i18n=i18n,
                                title=i18n.t("auth.edit_password_page_title")
                            )

                    if not self.password_accepted(
                        db_session, user, form.password.data
                    ):
                        # password may not be reused

                        # show message in form
                        form.password.errors.append(
                            i18n.t('auth.edit_password_cannot_reuse')
                        )

                        if token:
                            # set hidden field
                            form.reset_password_token.data = token

                        return render_template(
                            'edit_password.html', form=form, i18n=i18n,
                            title=i18n.t("auth.edit_password_page_title")
                        )

                    # save new password
                    user.set_password(form.password.data)
                    # clear force password change flag
                    user.force_password_change = False
                    # clear token
                    user.reset_password_token = None
                    # Reset signing fail count
                    user.failed_sign_in_count = 0
                    if user.last_sign_in_at is None:
                        # set last sign in timestamp after required password change
                        # to mark as password changed
                        user.last_sign_in_at = datetime.datetime.now(datetime.UTC)

                    if self.password_history_active:
                        # add new entry to password history
                        self.create_password_history(db_session, user)

                    flash(i18n.t("auth.edit_password_successful"))
                    target_url = unquote(form.url.data) or None
                    if not identity:
                        return redirect(url_for('login', url=target_url))
                    else:
                        return render_template(
                            'edit_password.html', form=form, i18n=i18n,
                            title=i18n.t("auth.edit_password_page_title")
                        )
                else:
                    # invalid reset token
                    flash(i18n.t("auth.edit_password_invalid_token"))
                    return render_template(
                        'edit_password.html', form=form, i18n=i18n,
                        title=i18n.t("auth.edit_password_page_title")
                    )

        if token:
            # set hidden field
            form.reset_password_token.data = token

        return render_template(
            'edit_password.html', form=form, i18n=i18n,
            title=i18n.t("auth.edit_password_page_title")
        )

    def require_password_change(self, user, reason, target_url):
        """Show form for required password change.

        :param User user: User instance
        :param str reason: Reason for this required password change
        :param str target_url: URL for redirect
        """
        # clear last sign in timestamp and generate reset token
        # to mark as requiring password change
        user.last_sign_in_at = None
        user.reset_password_token = self.generate_token()

        # show password reset form
        form = self.edit_password_form()
        form.logo = self.login_logo
        form.background = self.login_background
        form.customstylesheet = self.customstylesheet
        form.favicon = self.favicon
        # set hidden fields
        form.reset_password_token.data = user.reset_password_token
        form.url.data = target_url

        if reason == self.PASSWORD_CHANGE_REASON_REQUESTED:
            flash(i18n.t('auth.edit_password_reason_requested'))
        elif reason == self.PASSWORD_CHANGE_REASON_EXPIRED:
            flash(i18n.t('auth.edit_password_reason_expired'))

        flash(i18n.t('auth.edit_password_message'))
        return render_template(
            'edit_password.html', form=form, i18n=i18n,
            title=i18n.t("auth.edit_password_page_title")
        )

    def edit_password_form(self):
        """Return password reset form with constraints from config."""
        return EditPasswordForm(
            self.password_constraints['min_length'],
            self.password_constraints['max_length'],
            self.password_constraints['constraints'],
            self.password_constraints['min_constraints'],
            self.password_constraints['constraints_message'],
            meta=wft_locales()
        )

    def unlock_account(self, token):
        """Unlocks an account by token."""

        with self.db_session() as db_session, db_session.begin():
            # find user by password reset token
            user = self.find_user(db_session, reset_password_token=token)

            if user:
                user.failed_sign_in_count = 0
                user.reset_password_token = None
                flash(i18n.t("auth.account_unlocked"))
            else:
                flash(i18n.t("auth.invalid_unlock_token"))
        return redirect(url_for('login'))

    def db_session(self):
        """Return new session for ConfigDB."""
        return self.config_models.session()

    def find_user(self, db_session, **kwargs):
        """Find user by filter.

        :param Session db_session: DB session
        :param **kwargs: keyword arguments for filter (e.g. name=username)
        """
        return db_session.query(self.User).filter_by(**kwargs).first()

    def load_user(self, id):
        """Load user by id.

        :param int id: User ID
        """
        # create session for ConfigDB
        with self.db_session() as db_session:
            # find user by ID
            user = self.find_user(db_session, id=id)

        return user

    def token_exists(self, token):
        """Check if password reset token exists.

        :param str: Password reset token
        """
        # create session for ConfigDB
        with self.db_session() as db_session:
            # find user by password reset token
            user = self.find_user(db_session, reset_password_token=token)

        return user is not None

    def __user_is_authorized(self, user, password):
        """Check credentials, update user sign in fields and
        return whether user is authorized.

        :param User user: User instance
        :param str password: Password
        """
        remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        self.logger.info("Remote IP is %s" % remote_addr)
        # Check if IP blacklisted
        if self.ip_blacklist_duration > 0:
            entry = ip_blacklist.lookup(remote_addr)
            count = entry['value'] if entry else 0
            if count >= self.ip_blacklist_max_attempt_count:
                self.logger.info("IP %s is blacklisted with %s attempts" % (remote_addr, count))
                return False, i18n.t('auth.ip_blacklisted')

        if user is None or user.password_hash is None:
            # invalid username or no password set
            self.logger.debug("Invalid username or no password set for user")
            return False, i18n.t('auth.auth_failed')
        elif user.check_password(password):
            # valid credentials
            if user.failed_sign_in_count < self.max_login_attempts:
                if not self.__totp_is_enabled(user):
                    # update last sign in timestamp and reset failed attempts
                    # counter
                    user.last_sign_in_at = datetime.datetime.now(datetime.UTC)
                    user.failed_sign_in_count = 0

                self.logger.debug("User is authorized")
                return True, None
            else:
                # block sign in due to too many login attempts
                self.logger.debug("User is authorized but account is locked")
                return False, i18n.t('auth.account_locked')
        else:
            # invalid password

            # add to ip blacklist
            if self.ip_blacklist_duration > 0:
                entry = ip_blacklist.lookup(remote_addr)
                count = entry['value'] if entry else 0
                ip_blacklist.set(remote_addr, count + 1, self.ip_blacklist_duration)
                self.logger.info("Attempt count for IP %s: %s" % (remote_addr, count + 1))

            # increase failed login attempts counter
            user.failed_sign_in_count += 1

            if user.failed_sign_in_count < self.max_login_attempts:
                self.logger.debug("User is not authorized")
                return False, i18n.t('auth.auth_failed')
            else:
                self.logger.debug("User is not authorized, account is locked due to too many attempts")
                return False, i18n.t('auth.account_locked')

    def user_totp_is_valid(self, user, token):
        """Check TOTP token, update user sign in fields and
        return whether user is authorized.

        :param User user: User instance
        :param str token: TOTP token
        """
        if user is None or not user.totp_secret:
            # invalid user ID or blank TOTP secret
            return False
        elif pyotp.totp.TOTP(user.totp_secret).verify(token, valid_window=1):
            # valid token
            # update last sign in timestamp and reset failed attempts counter
            user.last_sign_in_at = datetime.datetime.now(datetime.UTC)
            user.failed_sign_in_count = 0

            return True
        else:
            # invalid token

            # increase failed login attempts counter
            user.failed_sign_in_count += 1

            return False

    def clear_verify_session(self):
        """Clear session values for TOTP verification."""
        session.pop('login_uid', None)
        session.pop('target_url', None)
        session.pop('totp_secret', None)
        session.pop('show_qrcode', None)

    def __login_response(self, user, target_url):
        self.logger.info("Logging in as user '%s'" % user.name)
        # flask_login stores user in session
        login_user(user)

        # Create the tokens we will be sending back to the user
        identity = {
            'username': user.name
        }
        # collect custom user info fields
        user_info = user.user_info
        for field in self.user_info_fields:
            if hasattr(user_info, field):
                identity[field] = getattr(user_info, field)
            else:
                self.logger.warning(
                    "User info field '%s' does not exist" % field
                )

        access_token = create_access_token(identity=identity)
        # refresh_token = create_refresh_token(identity=identity)

        # check if password will soon expire
        days = self.days_for_password_expiry_notice(user)
        if days == -1:
            # redirect to target URL
            resp = make_response(redirect(target_url))
        else:
            # dummy form for expiry notice with customization
            form = LoginForm()
            form.logo = self.login_logo
            form.background = self.login_background
            form.customstylesheet = self.customstylesheet
            form.favicon = self.favicon
            # show expiry notice
            page = render_template(
                'notification.html', form=form, i18n=i18n,
                title=i18n.t("auth.notification_page_title"),
                message=i18n.t("auth.notification_expiry_notice", days=days),
                target_url=target_url
            )
            resp = make_response(page)

        # Set the JWTs in this response
        set_access_cookies(resp, access_token)

        return resp

    def generate_token(self):
        """Generate new token."""
        token = None
        while token is None:
            # generate token
            token = base64.urlsafe_b64encode(os.urandom(15)). \
                rstrip(b'=').decode('ascii')

            # check uniqueness of token
            if self.token_exists(token):
                # token already present
                token = None

        return token

    def send_reset_passwort_instructions(self, user):
        """Send mail with reset password instructions to user.

        :param User user: User instance
        """
        # generate full reset password URL
        reset_url = url_for(
            'edit_password', reset_password_token=user.reset_password_token,
            _external=True
        )
        unlock_url = url_for(
            'unlock_account', reset_password_token=user.reset_password_token,
            _external=True
        )

        msg = Message(
            i18n.t('auth.reset_mail_subject'),
            recipients=[user.email]
        )
        # set message body from template
        try:
            msg.body = render_template(
                'reset_password_instructions.%s.txt' % i18n.get('locale'),
                user=user, reset_url=reset_url,
                unlock_url=unlock_url
            )
        except:
            msg.body = render_template(
                'reset_password_instructions.en.txt',
                user=user, reset_url=reset_url
            )

        # send message
        self.logger.debug(msg)
        self.mail.send(msg)

    def find_latest_password_history(self, db_session, **kwargs):
        """Find latest password history entry by filter.

        :param Session db_session: DB session
        :param **kwargs: keyword arguments for filter (e.g. user=user)
        """
        return db_session.query(self.PasswordHistory). \
            order_by(self.PasswordHistory.created_at.desc()). \
            filter_by(**kwargs).first()

    def create_password_history(self, db_session, user):
        """Create a new password history entry for a user and return it.

        :param Session db_session: DB session
        :param User user: User instance
        """
        pw_history = self.PasswordHistory(
            user=user,
            password_hash=user.password_hash,
            created_at=datetime.datetime.now(datetime.UTC)
        )
        db_session.add(pw_history)

        return pw_history

    def days_for_password_expiry_notice(self, user):
        """Return days until password expires within notice period, or -1
        (if password expiry and notice is enabled).

        :param User user: User instance
        """
        days_notice = -1

        expiry_notice = self.password_constraints['expiry_notice']
        if self.password_history_active and expiry_notice != -1:
            # password expiry notice is enabled
            # get days until expiry
            with self.db_session() as db_session:
                days_remaining = self.days_until_password_expiry(db_session, user)

            if days_remaining != -1 and days_remaining <= expiry_notice:
                # remaining days within notice period
                days_notice = days_remaining

        return days_notice

    def days_until_password_expiry(self, db_session, user):
        """Return days until password expires, or -1
        (if password expiry is enabled).

        :param Session db_session: DB session
        :param User user: User instance
        """
        days_remaining = -1

        expiry = self.password_constraints['expiry']
        if self.password_history_active and expiry != -1:
            # password expiry is enabled
            pw_history = self.find_latest_password_history(
                db_session, user=user
            )
            if pw_history:
                # calculate remaining days
                expires_at = pw_history.created_at.replace(tzinfo=datetime.UTC) + datetime.timedelta(days=expiry)
                if datetime.datetime.now(datetime.UTC) < expires_at:
                    delta = expires_at - datetime.datetime.now(datetime.UTC)
                    days_remaining = delta.days
                    if delta.seconds > 0:
                        # round up partial days
                        days_remaining += 1

        return days_remaining

    def password_has_expired(self, db_session, user):
        """Return whether a user's password has expired
        (if password expiry is enabled).

        :param Session db_session: DB session
        :param User user: User instance
        """
        expired = False

        expiry = self.password_constraints['expiry']
        if self.password_history_active and expiry != -1:
            # password expiry is enabled
            pw_history = self.find_latest_password_history(
                db_session, user=user
            )
            if (
                pw_history and
                datetime.datetime.now(datetime.UTC) >
                    pw_history.created_at.replace(tzinfo=datetime.UTC) + datetime.timedelta(days=expiry)
            ):
                # password has expired
                expired = True

        return expired

    def can_change_password(self, db_session, user):
        """Return whether a user may change the password again
        (if password update interval is set).

        :param Session db_session: DB session
        :param User user: User instance
        """
        allow_change = True

        update_interval = self.password_constraints['update_interval']
        if self.password_history_active and update_interval != -1:
            # password update interval is set
            pw_history = self.find_latest_password_history(
                db_session, user=user
            )
            # check time since last password update
            if (
                pw_history and
                datetime.datetime.now(datetime.UTC) <
                    pw_history.created_at.replace(tzinfo=datetime.UTC) + datetime.timedelta(seconds=update_interval)
            ):
                # time since last update was too short
                allow_change = False

        return allow_change

    def password_accepted(self, db_session, user, new_password):
        """Return whether a user's new password is accepted
        (if password reuse is not allowed).

        :param Session db_session: DB session
        :param User user: User instance
        :param str password: Password
        """
        accepted = True

        allow_reuse = self.password_constraints['allow_reuse']
        if self.password_history_active and not allow_reuse:
            # password reuse is not allowed
            # check password history of user
            pw_histories = db_session.query(self.PasswordHistory). \
                order_by('created_at').filter_by(user=user).all()
            for pw_history in pw_histories:
                # check new password against hash in history
                if check_password_hash(pw_history.password_hash, new_password):
                    # password has already been used
                    accepted = False
                    break

        return accepted


def wft_locales():
    return {'locales': [i18n.get('locale')]}


def url_path(url):
    """ Extract path and query parameters from URL """
    o = urlparse(url)
    parts = list(filter(None, [o.path, o.query]))
    return '?'.join(parts)
