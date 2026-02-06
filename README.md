[![](https://github.com/qwc-services/qwc-db-auth/workflows/build/badge.svg)](https://github.com/qwc-services/qwc-db-auth/actions)
[![docker](https://img.shields.io/docker/v/sourcepole/qwc-db-auth?label=Docker%20image&sort=semver)](https://hub.docker.com/r/sourcepole/qwc-db-auth)

Authentication with User DB
===========================

Authentication service with local user database.


Configuration
-------------

The static config files are stored as JSON files in `$CONFIG_PATH` with subdirectories for each tenant,
e.g. `$CONFIG_PATH/default/*.json`. The default tenant name is `default`.

### DB Auth Service config

* [JSON schema](schemas/qwc-db-auth.json)
* File location: `$CONFIG_PATH/<tenant>/dbAuthConfig.json`

Example:
```json
{
  "$schema": "https://raw.githubusercontent.com/qwc-services/qwc-db-auth/master/schemas/qwc-db-auth.json",
  "service": "db-auth",
  "config": {
    "db_url": "postgresql:///?service=qwc_configdb"
  }
}
```

### Environment variables

Config options in the config file can be overridden by equivalent uppercase environment variables.

In addition, the following environment variables are supported:

| Name                         | Default       | Description                                                                               |
|------------------------------|---------------|-------------------------------------------------------------------------------------------|
| `JWT_COOKIE_SECURE`          | `False`       | See [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/en/stable/options.html#JWT_COOKIE_SECURE). |
| `JWT_COOKIE_SAMESITE`        | `Lax`         | See [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/en/stable/options.html#JWT_COOKIE_SAMESITE). |
| `JWT_ACCESS_TOKEN_EXPIRES`   | `12*3600`     | See [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/en/stable/options.html#JWT_ACCESS_TOKEN_EXPIRES). |
| `MAIL_SERVER`                | `localhost`   | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_PORT`                  | `25`          | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_USE_TLS`               | `False`       | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_USE_SSL`               | `False`       | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_DEBUG`                 | `app.debug`   | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_USERNAME`              | `None`        | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_PASSWORD`              | `None`        | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_DEFAULT_SENDER`        | `None`        | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_MAX_EMAILS`            | `None`        | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_SUPPRESS_SEND`         | `app.testing` | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |
| `MAIL_ASCII_ATTACHMENTS`     | `False`       | Mailer setup, see [Flask-Mail](https://flask-mail.readthedocs.io/en/latest/#configuring). |


Set the `MAX_LOGIN_ATTEMPTS` environment variable to set the maximum number of
failed login attempts before sign in is blocked (default: `20`).

### Password constraints

A minimum password length of `8` with no other constraints is set by default. Optional password complexity constraints can be set using the following options:
```json
"config": {
  "password_min_length": 8,
  "password_max_length": 128,
  "password_constraints": [
      "[A-Z]",
      "[a-z]",
      "\\d",
      "[ !\"#$%&'()*+,\\-./\\\\:;<=>?@\\[\\]^_`{|}~]"
  ],
  "password_min_constraints": 3,
  "password_constraints_message": "Password must contain at least three of these character types: uppercase letters, lowercase letters, numbers, special characters"
}
```

`password_min_length` and `password_max_length` can be set independently. `password_constraints` is a list of regular expression of which at least `password_min_constraints` have to match for the password to be valid, otherwise the `password_constraints_message` is shown. Note that the regular expression have to be JSON escaped and allow only patterns supported by Python's `re` module.

If the `qwc_config.password_histories` table is present, additional optional password constraints may be set:
```json
"config": {
  "password_expiry": 365,
  "password_expiry_notice": 10,
  "password_update_interval": 600,
  "password_allow_reuse": false
}
```

* `password_expiry` (default: `-1`): Number of days until a password expires, or `-1` to disable. Forces a password change once expired.
* `password_expiry_notice` (default: `-1`): Show an expiry notice within this number of days before a password expires, or `-1` to disable
* `password_update_interval` (default: `-1`): Min number of seconds before a password may be changed again, or `-1` to disable
* `password_allow_reuse` (default: `true`): Set whether a user may reuse previous passwords or not


### Plaintext POST login

Besides the form based DB login, an (insecure) plain POST login is supported. This method can be
activated by setting `post_param_login` to `true`. User and password are passed as POST parameters
`username` and `password`.

Usage example: `curl -d 'username=demo&password=demo' http://localhost:5000/login`.

### JWT user info fields

Additional user info fields from the `qwc_config.user_infos` table from the QWC Config DB may be included in the issued JWT identity by setting `user_info_fields`:

```json
"config": {
  "user_info_fields": ["surname", "first_name"]
}
```

### Two factor authentication

Two factor authentication using TOTP can be enabled by setting `totp_enabled` to `true`.
This will require an additional verification token after sign in, based on the user's TOTP secret.

A personal QR code for setting up the two factor authentication is shown to the user on first sign in (or if the TOTP secret is empty).
The TOTP issuer name for your application can set via `totp_issuer_name`.

An user's TOTP secret can be reset by clearing it in the Admin GUI user form.


### Appearance customization

You can add a custom logo and a custom background image by setting the following `config` options:

```json
"config": {
  "background_image_url": "<url>",
  "logo_image_url": "<url>"
}
```

The specified URLs can be absolute or relative. For relative URLs, you can write i.e.

```json
"config": {
  "background_image_url": "/auth/static/background.jpg",
  "logo_image_url": "/auth/static/logo.jpg"
}
```

where `/auth` is the service mountpoint and place your custom images inside the `static` subfolder of the auth-service, or, if using docker and docker-compose, mount them accordingly:

    qwc-auth-service:
      [...]
      volumes:
        - ./volumes/assets/Background.jpg:/srv/qwc_service/static/background.jpg
        - ./volumes/assets/logo.png:/srv/qwc_service/static/logo.jpg

If you want to override some styles, you can set the `customstylesheet` option to the name of a file below the `static` subfolder of the auth-service, and it will get included into the base template.

Run locally
-----------

Install dependencies and run:

    # Setup venv
    uv venv .venv

    export CONFIG_PATH=<CONFIG_PATH>
    uv run src/server.py

To use configs from a `qwc-docker` setup, set `CONFIG_PATH=<...>/qwc-docker/volumes/config`.

Set `FLASK_DEBUG=1` for additional debug output.

Set `FLASK_RUN_PORT=<port>` to change the default port (default: `5000`).

Docker usage
------------

The Docker image is published on [Dockerhub](https://hub.docker.com/r/sourcepole/qwc-db-auth).

See sample [docker-compose.yml](https://github.com/qwc-services/qwc-docker/blob/master/docker-compose-example.yml) of [qwc-docker](https://github.com/qwc-services/qwc-docker).
