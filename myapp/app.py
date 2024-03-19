from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from flask_restx import Api
from flask_login import (LoginManager,  
                         AnonymousUserMixin)

from flask_migrate import Migrate
from flask_principal import Principal
from flask_babel import Babel

from loguru import logger
from datetime import timedelta

import os
from flask_caching import Cache
from flask_session import Session
from redis import Redis
from flask_bootstrap import Bootstrap5
from flask_cors import CORS

db = SQLAlchemy()

def create_app(config_filename=None):
    app = Flask(__name__, static_folder='build', static_url_path='/')

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///picwe.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['BABEL_DEFAULT_LOCALE'] = 'en'
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
    app.config['SECRET_KEY'] = ''
    app.config['UPLOAD_FOLDER'] = 'uploads/'
    app.config['UPLOADED_FILES_DEST'] = os.path.join(
        os.path.dirname(__file__), app.config['UPLOAD_FOLDER'])
    app.config['USE_RATE_LIMITER'] = False 
    app.config['RESIZE_URL'] = '/resize/'
    app.config['RESIZE_ROOT'] = 'myapp/uploads' 
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = Redis(host='localhost', port=6379)

    db.init_app(app)
    return app

app = create_app()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

CORS(app)
bootstrap = Bootstrap5(app)
Session(app)
api = Api(app, doc='/doc', title="PicWe API", version="1.0")
migrate = Migrate(app, db)
principals = Principal(app)
babel = Babel(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()
cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0'
})

logger.add('app.log', format="{time} {level} {message}", level="DEBUG", rotation="10 MB", compression="zip")
   
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_admin"
login_manager.remember_cookie_duration = timedelta(days=1)

class AnonymousUser(AnonymousUserMixin):
    def is_admin(self):
        return False
login_manager.anonymous_user = AnonymousUser

proxy = ''
status_of_pro = 1



    
