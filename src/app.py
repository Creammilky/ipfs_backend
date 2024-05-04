import json

from flask import Flask, render_template, redirect, url_for, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, login_required, login_user
from accounts.config import Config
from accounts.user import db, User
from accounts.auth import auth_blueprint

app = Flask(__name__)
app.secret_key = 'your_secret_key_here___'
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

app.register_blueprint(auth_blueprint, url_prefix='/auth')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('index_log'))
    return render_template('index.html')

@app.route('/user')
@login_required
def index_log():
    return render_template('index_log.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def signin():
    return render_template('login.html')

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    return render_template('register.html')

@app.route('/sign-up-client', methods=['POST'])
def sign_up_client():
    if current_user.is_authenticated:
        return jsonify({'message': 'User already logged in'}), 400

    data = json.loads(request.get_json())  # 获取POST的JSON数据
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')  # 从JSON获取公钥

    if not username or not password or not public_key:
        return jsonify({'message': 'Missing username, password, or public key'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 409

    new_user = User(
        username=username,
        public_key=public_key,  # 设置公钥
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)
    return jsonify({'message': 'User successfully registered'}), 201

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')