from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash

class LoginForm(FlaskForm):
    Username= StringField('username', validators=[DataRequired(), Length(min = 2, max = 20)])
    Password = PasswordField('passowrd', validators=[DataRequired(), Length(min = 8, max = 20)])
    Remember = BooleanField('Remember Me')
    Submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    Username= StringField('username', validators=[DataRequired(), Length(min = 2, max = 20)])
    Password = PasswordField('passowrd', validators=[DataRequired(), Length(min = 8, max = 20)])
    ConfirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('Password')])
    Submit = SubmitField('Register')
