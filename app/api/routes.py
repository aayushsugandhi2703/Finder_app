from flask import Flask, Blueprint, render_template, redirect, url_for, flash, jsonify, make_response, session
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity    
from app.Models.models import User, Session
from app.Forms.forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_user, logout_user, login_required

api_bp = Blueprint('api', __name__)

limiter = Limiter(key_func=get_remote_address, default_limits=["5 per minute"])

# This function will redirect the user to the login page
@api_bp.route('/', methods=['GET'])
def index():
    return redirect(url_for('api.Login'))

# This function and route is for the user to login 
@api_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def Login():
    form = LoginForm()

    # If the form is submitted and validated, the user will be redirected to the task page
    if form.validate_on_submit(): 
        user = Session.query(User).filter_by(username=form.username.data).first()
        if user and user.password == check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id

            # Create the access and refresh tokens
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)

            response = make_response(redirect(url_for('api.login')))
            response.set_cookie('access_token_cookie', access_token, httponly=True)
            response.set_cookie('refresh_token_cookie', refresh_token, httponly=True)
            login_user(user)

            return response 
      # return jsonify(access_token=access_token, refresh_token=refresh_token)
    return render_template('Login.html', form=form)

# This function and route is for the user to register
@api_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def Register():
    form = RegisterForm()

    # If the form is submitted and validated, the user will be redirected to the login page
    if form.validate_on_submit():
        passcode = generate_password_hash(form.password.data)  
        user = User(username=form.username.data, password=passcode)
        Session.add(user)
        Session.commit()
        flash('User created successfully')
        return redirect(url_for('api.Login'))
    else:
        Session.rollback()
        flash('User creation failed')
    return render_template('Register.html', form=form)

# This function and route is for the user to logout
@api_bp.route('/logout', methods=['GET'])  
@login_required
def Logout():

    response = make_response(redirect(url_for('api.Login')))
    response.delete_cookie('access_token_cookie')  # Ensure you delete the correct cookie
    response.delete_cookie('refresh_token_cookie')  # Also delete the refresh token
    logout_user()
    session.clear()
    return response

