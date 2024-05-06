from flask import Blueprint, request, redirect, render_template, url_for, flash, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from .user import User, db, Group, IPFSFile
from werkzeug.security import check_password_hash


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

def create_group(name, owner_id):
    new_group = Group(name=name, owner_id=owner_id)
    db.session.add(new_group)
    db.session.commit()

def join_group(user_id, group_id):
    user = User.query.get(user_id)
    group = Group.query.get(group_id)
    if group not in user.groups:
        user.groups.append(group)
        db.session.commit()

def leave_group(user_id, group_id):
    user = User.query.get(user_id)
    group = Group.query.get(group_id)
    if group in user.groups:
        user.groups.remove(group)
        db.session.commit()


def upload_file_to_ipfs(user_id, cid, filename, description, access_type, access_id, encrypted_key):
    new_file = IPFSFile(
        uploader_id=user_id,
        cid=cid,
        filename=filename,
        description=description,
        access_type=access_type,
        access_id=access_id,
        encrypted_key=encrypted_key
    )
    db.session.add(new_file)
    db.session.commit()
