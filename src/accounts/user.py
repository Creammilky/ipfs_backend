from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# 定义多对多关联表
user_groups = db.Table('user_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id'), primary_key=True)
)

# 定义User模型
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    hashed_password = db.Column(db.String(500))
    public_key = db.Column(db.String(512))
    groups = db.relationship('Group', secondary=user_groups, backref=db.backref('members', lazy='dynamic'))

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password, method='pbkdf2')

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)

# 定义Group模型
class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class IPFSFile(db.Model):
    __tablename__ = 'ipfs_files'
    id = db.Column(db.Integer, primary_key=True)
    cid = db.Column(db.String(128), unique=True, nullable=False)  # IPFS中的唯一hash
    filename = db.Column(db.String(128), nullable=False)  # 文件名
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 上传者ID
    access_type = db.Column(db.String(10), nullable=True)  # 访问权限类型，'user' 或 'group'
    # 存储多个访问ID
    access_ids = db.Column(db.PickleType, nullable=True)  # 使用PickleType来存储列表
    description = db.Column(db.String(512))  # 文件描述
    encrypted_key = db.Column(db.String(512))  # 加密的对称密钥

    uploader = db.relationship('User', backref=db.backref('uploaded_files', lazy=True))

