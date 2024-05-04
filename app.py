from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, login_required
from user.config import Config
from user.models import db, User
from user.auth import auth_blueprint

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

if __name__ == '__main__':
    app.run(debug=True)
