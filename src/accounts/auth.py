from flask import Blueprint, request, redirect, render_template, url_for, flash, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from sqlalchemy.exc import SQLAlchemyError

from .user import User, db, Group, IPFSFile
from werkzeug.security import check_password_hash

from src.cypher.interfaces import *

auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        public_key = request.form.get('public_key')  # 从表单获取公钥

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')

        new_user = User(
            username=username,
            public_key=public_key,  # 设置公钥
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('register.html')

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index_log'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index_log'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


@auth_blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


def create_group(groupname, username):
    try:
        user_id = User.query.filter_by(username=username).first().id
        new_group = Group(name=groupname, owner_id=user_id)
        db.session.add(new_group)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        raise  # 或者根据需要处理异常

# 加入组
def join_group(username, groupname):
    try:
        user = User.query.filter_by(username=username).first()
        group = Group.query.filter_by(name=groupname).first()
        if group and user and group not in user.groups:
            user.groups.append(group)
            db.session.commit()
        else:
            raise ValueError("Group or user not found or user is already in the group.")
    except SQLAlchemyError as e:
        db.session.rollback()
        raise  # 或者根据需要处理异常

# 离开组
def leave_group(username, groupname):
    try:
        user = User.query.filter_by(username=username).first()
        group = Group.query.filter_by(name=groupname).first()
        if group and user and group in user.groups and user.id != group.owner_id:
            user.groups.remove(group)
            db.session.commit()
        else:
            raise ValueError("Group or user not found or user is not in the group or user is the owner.")
    except SQLAlchemyError as e:
        db.session.rollback()
        raise  # 或者根据需要处理异常


def upload_file_to_ipfs(username, cid, filename, description, access_type=None, access_ids=None, encrypted_key=None):
    try:
        user = User.query.filter_by(username=username).first()
        print(access_ids)
        new_file = IPFSFile(
            uploader_id=user.id,
            cid=cid,
            filename=filename,
            description=description,
            access_type=access_type,
            access_ids=access_ids,
            encrypted_key=encrypted_key.encode('utf-8')
        )
        db.session.add(new_file)
        db.session.commit()
        return (None, 200)
    except Exception as e:
        return (str(e), 400)


def check_permission(user, ipfs_file):
    # 检查访问类型是否为空，如果为空直接返回True
    if not ipfs_file.access_type:
        return True

    # 获取访问列表
    access_ids = ipfs_file.access_ids

    # 判断访问权限类型
    if ipfs_file.access_type == 'user':
        # 如果权限类型是'user'，检查用户 ID 是否在列表中
        # 同时需要处理access_ids为空的情况
        return access_ids is None or user.id in access_ids
    elif ipfs_file.access_type == 'group':
        # 如果权限类型是'group'，检查用户是否属于列表中的任何一个组
        # 同样需要处理access_ids为空的情况
        if access_ids is None:
            return False  # 根据业务逻辑，这里可能是False或True
        for group_id in access_ids:
            group = Group.query.get(group_id)
            if group and user in group.members:
                return True
        return False
    else:
        return False
    # 如果所有检查都没有通过，则默认用户没有权限
    return False


def download_file_from_ipfs(username, cid):
    # 获取用户实例
    server_prikey = 'C:\\Users\\YaoJia\\Desktop\\安全编程技术\\ipfs_backend\\pem\\private_key.pem'
    user = User.query.filter_by(username=username).first()
    if not user:
        return (None, 404)  # 用户不存在

    # 获取文件实例
    ipfs_file = IPFSFile.query.filter_by(cid=cid).first()
    if not ipfs_file:
        return (None, 404)  # 文件不存在

    if check_permission(user, ipfs_file):

        ipfs_file_encrypted_key = ipfs_file.encrypted_key
        ipfs_file_key = decrypt_message(ipfs_file_encrypted_key, server_prikey, is_plain=False)
        user_pubkey = user.public_key
        ipfs_file_encrypted_key2 = encrypt_message(ipfs_file_key, user_pubkey, is_plain=True)
        return (ipfs_file_encrypted_key2, 200)
    else:
        print("没有权限下载该文件")
        return (None ,403)
