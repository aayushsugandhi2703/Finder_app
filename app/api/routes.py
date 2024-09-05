from flask import Flask, render_template, request, flash, session, jsonify, make_response, Response, current_app
from app.Models.models import User, Session
from app.Forms.forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from app.api import api_bp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# initializing hte limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# login route for api 
@api_bp.route('/login', methods=['POST'])  
def login():
    form = LoginForm(data=request.get_json())  # Pass JSON data to the form
    if form.validate():
        user = Session.query(User).filter_by(username=form.username.data).first()  
        if user and check_password_hash(user.password, form.password.data):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            current_app.logger.info(f'{user.username} has logged in') 
            return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
        else:
            current_app.logger.error(f'Invalid credentials for {form.username.data}')  # Form data for logging
            return jsonify({'message': 'Invalid credentials'}), 401
    else:
        return jsonify({'message': 'Invalid data provided'}), 400
    
# register route for api
@api_bp.route('/Register', methods=['POST'])
def register():
    form = RegisterForm(data=request.get_json())  # Pass JSON data to the form
    if form.validate_on_submit():  # This validates the form based on the provided JSON
        user = Session.query(User).filter_by(username=form.username.data).first()
        if user:
            return jsonify({'message': 'User already exists'}), 401
        try:
            new_user = User(username=form.username.data, password=generate_password_hash(form.password.data))
            Session.add(new_user)
            Session.commit()
            current_app.logger.info(f'{new_user.username} has registered')
            return jsonify({'message': 'User has been registered'}), 200
        except Exception as e:
            Session.rollback()
            current_app.logger.error(f'Error during registration: {str(e)}')
            return jsonify({'message': 'Error occurred during registration'}), 500
    else:
        return jsonify({'message': 'Invalid data provided'}), 400
