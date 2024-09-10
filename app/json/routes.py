from flask import Flask, Blueprint, render_template, redirect, url_for, flash, jsonify, make_response, current_app,request
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity    
from app.Models.models import User, Session, Contact
from app.Forms.forms import LoginForm, RegisterForm, ContactForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["5 per minute"])

json_bp = Blueprint('json', __name__)


@json_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = Session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            current_app.logger.info(f"User {username} logged in successfully")
            return jsonify(access_token=access_token, refresh_token=refresh_token, username=username, id=user.id,password=user.password) 
        else:
            current_app.logger.error(f"User {username} failed to login")
            flash('Invalid username or password')
    
    return render_template('Login.html', form=form)

@json_bp.route('/add', methods=['GET', 'POST'])
def add():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        phone = form.phone.data
        user_id = get_jwt_identity()
        contact = Contact(name=name, phone=phone, user_id=user_id)
        Session.add(contact)
        Session.commit()
        current_app.logger.info(f"User {user_id} added a contact")
        return jsonify(name=name, phone=phone, user_id=user_id)
    return render_template('Add.html', form=form)
    