from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.numeric import IntegerField
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange, Optional
from models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')


class PassChangeForm(FlaskForm):
    old_password = StringField('OldPassword', validators=[DataRequired()])
    new_password = StringField('NewPassword', validators=[DataRequired()])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class TaskForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    type = StringField('Type', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    status = IntegerField('Status', validators=[NumberRange(min=0, max=3)])


class TaskUpdateForm(FlaskForm):
    name = StringField('Name', validators=[Optional()])
    type = StringField('Type', validators=[Optional()])
    description = StringField('Description', validators=[Optional()])
    status = IntegerField('Status', validators=[Optional(), NumberRange(min=0, max=3)])
