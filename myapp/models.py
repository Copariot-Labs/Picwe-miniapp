

from flask_login import UserMixin
from myapp.app import app,db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


engine = create_engine('sqlite://picwe')
Session = sessionmaker(bind=engine)

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

################################  
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    avatar_name = db.Column(db.String(120), nullable=True)
    avatar_image_filename = db.Column(db.String(120), nullable=True)
    posts = db.relationship('Post', back_populates='user')
    likes = db.relationship('LikeModel', backref='user', lazy=True)
    assets = db.relationship('Asset', backref='owner', lazy=True)
    user_key = db.relationship('UserKey', backref='key_owner', uselist=False)
    orders = db.relationship('Order', backref='user', lazy=True)
    is_telegram_user = db.Column(db.Boolean, default=False)
    telegram_id = db.Column(db.String(64), unique=True, nullable=True)
    last_login_date = db.Column(db.DateTime, default=None)
    invitation_code = db.Column(db.String(64), unique=True)
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    inviter = db.relationship('User', remote_side=[id], backref='invitees')
    web3_address = db.Column(db.String(64), unique=True, nullable=True)  # 增加一个地址
    is_web3_user = db.Column(db.Boolean, default=False)  # 判断是否metamask用户
    favorites = db.relationship('Favorite', backref='user', lazy='dynamic')
    attributes = db.relationship('UserAttribute', backref='user', lazy=True)

with app.app_context():
    db.create_all()
    db.session.commit()