from flask import Flask
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
from flask_login import LoginManager
from app.Models.models import User, Session

jwt = JWTManager()
def create_app():
    app = Flask(__name__)
    
# configurations
    from config import Config 
    app.config.from_object(Config)

# initialize the json web token
    jwt.init_app(app)

#initializing the login manager
    login_manager = LoginManager()
    login_manager.login_view = 'api.Login'
    login_manager.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'api.Login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return Session.query(User).get(int(user_id))
    
#initializing hte limiter
    limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
    limiter.init_app(app)
    
#configurint the logger
    handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)

    handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler.setFormatter(formatter)

    app.logger.addHandler(handler)

#import the blueprints
    from app.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/')

    from app.json.routes import json_bp
    app.register_blueprint(json_bp, url_prefix='/json')
    
    return app