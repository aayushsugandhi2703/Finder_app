from flask import Flask
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler

jwt = JWTManager()
def create_app():
    app = Flask(__name__)
    
# configurations
    from config import Config 
    app.config.from_object(Config)

# initialize the json web token
    jwt.init_app(app)

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
    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    return app