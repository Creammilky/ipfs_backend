from datetime import timedelta
from flask import Flask, jsonify, request, make_response
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from accounts.config import Config
from accounts.user import db, User
from accounts.operate import auth_blueprint, upload_file_to_ipfs, download_file_from_ipfs, create_group, join_group, \
    leave_group, user_search, search_user_group, search_group_info

app = Flask(__name__)
app.secret_key = 'your_secret_key_here___'
app.config.from_object(Config)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this in your production settings
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=3)  # Token expires in one hour

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

app.register_blueprint(auth_blueprint, url_prefix='/auth')

@app.route('/sign-up-client', methods=['POST'])
def sign_up_client():
    try:
        data = request.get_json()  # 获取POST的JSON数据
    except Exception as e:
        print(e)

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
    return jsonify({'message': 'User successfully registered'}), 201

@app.route('/sign-in-client', methods=['POST'])
def sign_in_client():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        response = make_response(jsonify(access_token=access_token), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(jsonify({'message': 'Invalid credentials'}), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return 'You are now logged out!', 200

@app.route('/upload-file', methods=['POST'])
@jwt_required()
def upload_file():
    username = get_jwt_identity()
    # 从请求中获取 JSON 数据
    data = request.json

    # 提取 JSON 数据中的参数
    cid = data.get('cid')
    filename = data.get('filename')
    description = data.get('description')
    access_type = data.get('access_type')
    access_ids = data.get('access_ids')
    encrypted_key = data.get('encrypted_key')

    # 调用函数处理数据
    try:
        exception, response = upload_file_to_ipfs(username, cid, filename, description, access_type, access_ids, encrypted_key)
    except Exception as e:
        print('File uploaded failed by' + e)
        return jsonify({'message': 'File uploaded failed by' + e}), 401

    if response != 200:
        print('File uploaded failed by' + exception)
        return jsonify({'message': f'File uploaded failed caused by {exception}'}), response
    else:
        return jsonify({'message': 'File uploaded successfully'}), response

@app.route('/search-files', methods=['POST'])
@jwt_required()
def search_files():
    username = get_jwt_identity()
    data = request.get_json()
    filename = data.get('filename')

    try:
        results, response = user_search(filename, username)
        if response == 200:
            return jsonify(results), 200
        else:
            return jsonify({'message': 'File search failed'}), response
    except Exception as e:
        return jsonify({'message': f'File search failed: {str(e)}'}), 500


@app.route('/download-file', methods=['POST'])
@jwt_required()
def download_file():
    # 从请求中获取 JSON 数据
    data = request.json

    # 提取 JSON 数据中的参数
    username = data.get('username')
    cid = data.get('cid')

    # 调用函数处理数据
    try:
        ipfs_file_encrypted_key, response = download_file_from_ipfs(username, cid)
    except Exception as e:
        return jsonify({'message': f'File download failed by {e}'}), 401
    # 返回响应
    if response != 200:
        return jsonify({'message': 'File download failed'}), response
    else:
        return jsonify({'message': 'File successfully downloaded', 'file_key': f'{ipfs_file_encrypted_key}'}), 200

# 创建组的路由
@app.route('/create_group', methods=['POST'])
@jwt_required()
def create_group_route():
    username = get_jwt_identity()
    data = request.get_json()
    groupname = data.get('groupname')
    if not groupname or not username:
        return jsonify({'error': 'Missing groupname or username'}), 400
    try:
        create_group(groupname, username)
        return jsonify({'message': 'Group created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 加入组的路由
@app.route('/join_group', methods=['POST'])
@jwt_required()
def join_group_route():
    username = get_jwt_identity()
    data = request.get_json()
    groupname = data.get('groupname')
    if not username or not groupname:
        return jsonify({'error': 'Missing username or groupname'}), 400
    try:
        join_group(username, groupname)
        return jsonify({'message': 'User joined group successfully'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 离开组的路由
@app.route('/leave_group', methods=['POST'])
@jwt_required()
def leave_group_route():
    username = get_jwt_identity()
    data = request.get_json()
    groupname = data.get('groupname')
    if not username or not groupname:
        return jsonify({'error': 'Missing username or groupname'}), 400
    try:
        leave_group(username, groupname)
        return jsonify({'message': 'User left group successfully'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 请求所在组列表
@app.route('/user_group', methods=['POST'])
@jwt_required()
def user_group_route():
    username = get_jwt_identity()
    try:
        group_names = search_user_group(username)
        return jsonify({'groups': group_names}), 200  # Return the list of groups as JSON
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 特定组成员 以及 所上传的文件
@app.route('/group_info', methods=['POST'])
@jwt_required()
def group_info_route():
    username = get_jwt_identity()
    data = request.get_json()
    groupname = data.get('groupName')
    if not groupname:
        return jsonify({'error': 'Group name is required'}), 400

    try:
        group_users, group_files = search_group_info(username, groupname)
        return jsonify({
            'group_users': group_users,
            'group_files': group_files
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5008)