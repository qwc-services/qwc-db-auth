import re

from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, PasswordField, PasswordField, \
    StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')
    logo = "http://qwc2.sourcepole.ch/assets/img/logo.svg"
    background = ""
    terms_url = "https://qgis.org/en/site/"


class VerifyForm(FlaskForm):
    token = StringField('Verification code', validators=[DataRequired()])


class NewPasswordForm(FlaskForm):
    user = StringField('User', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])


class EditPasswordForm(FlaskForm):
    reset_password_token = HiddenField(validators=[Optional()])
    url = HiddenField(validators=[Optional()])
    old_password = PasswordField(
        'Current password'
    )
    password = PasswordField(
        'New password'
    )
    password_confirmation = PasswordField(
        'Confirm new password',
        validators=[DataRequired(), EqualTo('password')]
    )

    def __init__(self, min_length, max_length, constraints, min_constraints,
                 constraints_message, **kwargs):
        """Constructor

        :param int min_length: Min password length (-1 for none)
        :param int max_length: Max password length (-1 for none)
        :param list(str) constraints: List of custom constraints as RegEx
        :param int min_constraints: Min number of constraints to meet
        :param constraints_message: Message if constraints are not met
        """
        # set dynamic validators for password field
        validators = [
            DataRequired(),
            Length(min=min_length, max=max_length)
        ]
        self.password.kwargs['validators'] = validators

        # store constraints
        self.constraints = constraints
        self.min_constraints = min_constraints
        self.constraints_message = constraints_message

        super(EditPasswordForm, self).__init__(**kwargs)

    def validate_password(self, field):
        """Validate password constraints.

        :param Field field: Password field
        """
        # count number of validated constraints
        constraints_met = 0
        for constraint in self.constraints:
            if re.search(constraint, field.data):
                # constraint validated
                constraints_met += 1

        if constraints_met < self.min_constraints:
            raise ValidationError(self.constraints_message)
