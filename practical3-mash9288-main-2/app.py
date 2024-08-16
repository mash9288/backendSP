from flask import Flask, request, jsonify
from models import (
    initialize_database, create_user, create_user_profile, update_user_profile,
    create_user_image, get_user_by_id, get_user_details_by_id, delete_user_by_id,
    authenticate_user, authenticate_user_jwt, create_role, get_role_by_id, update_role_by_id, delete_role_by_id, get_all_roles
)
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from auth import admin_required
from flask_cors import CORS
import os
from extensions import db
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

 
app = Flask(__name__)
CORS(app)
config_class = os.getenv('FLASK_CONFIG', 'DevelopmentConfig')
app.config.from_object(f'config.{config_class}')
app.config['UPLOAD_FOLDER'] = './static/images'
jwt = JWTManager()


# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
 
db.init_app(app)
jwt.init_app(app)
 
with app.app_context():
    initialize_database()


# Define a simple Model for demonstration
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

# # Initialize the database
# @app.before_first_request
# def create_tables():
#     db.create_all()

# Pagination route using SQLAlchemy ORM
@app.route('/users')
def get_users():
    # Retrieve 'page' query parameter from the request, default to 1 if not provided, convert to integer
    page = request.args.get('page', 1, type=int)
    # Retrieve 'per_page' query parameter from the request, default to 10 if not provided, convert to integer
    per_page = request.args.get('per_page', 10, type=int)
    # Paginate User model results based on page number and items per page, without raising an error if out of range
    users_paginated = User.query.paginate(page=page, per_page=per_page, error_out=False)
    # Extract user details into a list of dictionaries
    users = [{'id': user.id, 'username': user.username, 'email': user.email} for user in users_paginated.items]
    # Return JSON response containing user details, total count, number of pages, current page, and pagination info
    return jsonify({
        'users': users,
        'total': users_paginated.total,
        'pages': users_paginated.pages,
        'page': page
    })

# Pagination route using raw SQL
@app.route('/users_sql')
def get_users_sql():
    # Retrieve 'page' query parameter from the request, default to 1 if not provided, convert to integer
    page = request.args.get('page', 1, type=int)
    # Retrieve 'per_page' query parameter from the request, default to 10 if not provided, convert to integer
    per_page = request.args.get('per_page', 10, type=int)
    # Calculate offset based on current page and items per page
    offset = (page - 1) * per_page
    # Construct SQL query string using formatted string literals for LIMIT and OFFSET clauses
    sql = f"SELECT * FROM user LIMIT {per_page} OFFSET {offset}"
    # Execute raw SQL query to retrieve paginated user records
    result = db.engine.execute(sql)
    # Extract user details from query result into a list of dictionaries
    users = [{'id': row[0], 'username': row[1], 'email': row[2]} for row in result]
    # Return JSON response containing user details
    return jsonify(users)


# LOGIN-JWT
@app.route('/login-jwt', methods=['POST'])
def loginjwt():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    # Attempt to authenticate the user
    access_token = authenticate_user_jwt(username, password)
    if access_token:
        # If authentication is successful, return the access token
        return jsonify(access_token=access_token), 200
    else:
        # If authentication fails, return an error message
        return jsonify({"msg": "Bad username or password"}), 401


# PROTECTED ROUTE
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
 

# PROTECTED ROUTE WITH ADMIN ROLE
@app.route('/protected_admin', methods=['GET'])
@jwt_required()
@admin_required
def protected_admin():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
 

#1 REGISTER/CREATE USER
@app.route('/register', methods=['POST'])
def register_user_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role_name = data.get('role_name')
 
    try:
        user_id = create_user(username, password, email, role_name)
        return jsonify({"message": "User created successfully", "user_id": user_id}), 201
    except Exception as e:
        return jsonify({"error": "User creation failed", "details": str(e)}), 400
 

#2 USER LOGIN
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_id = authenticate_user(username, password)
    if user_id:
        # For simplicity, returning a message;
        return jsonify({'message': 'Login successful', 'user_id': user_id}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401
 

#3 CREATE USER PROFILE WITH USER ID
@app.route('/user_profile/<int:user_id>', methods=['POST'])
def create_user_profile_route(user_id):
    data = request.get_json()
    profile_data = data.get('profile')
    try:
        user_profile_id = create_user_profile(user_id, profile_data)
        return jsonify({"message": "User Profile created successfully", "profile_id": user_profile_id}), 201
    except Exception as e:
        return jsonify({"error": "Failed to create user profile", "details": str(e)}), 400
 

#4 CREATE A USER IMAGE WITH USER ID
@app.route('/user_image', methods=['POST'])
def create_user_image_route():
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['image']
 
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
 
        image_url = filepath
        user_id = request.form.get('user_id')
        image_name = request.form.get('image_name')
        try:
            image_id = create_user_image(user_id, image_name, image_url)
            return jsonify({"message": "User Image created successfully", "image_id": image_id}), 201
        except Exception as e:
            return jsonify({"error": "Failed to create image", "details": str(e)}), 400
 
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 

#5 GET USER WITH USER ID
@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_by_id_route(user_id):
    user = get_user_by_id(user_id)
    if user:
        return jsonify(user)
    else:
        return jsonify({"error": "User not found"}), 404
 

#6 GET USER DETAILS WITH USER ID
@app.route('/user_details/<int:user_id>', methods=['GET'])
def get_user_details_by_id_route(user_id):
    user = get_user_details_by_id(user_id)
    if user:
        return jsonify(user), 200
    else:
        return jsonify({"error": "User not found"}), 404
 

#7 UPDATE USER WITH USER ID
@app.route('/user/<int:user_id>', methods=['PUT'])
def update_user_route(user_id):
    data = request.get_json()
    user = update_user(user_id, data['username'], data['email'])
    if user:
        return jsonify(user)
    else:
        return jsonify({"error": "User not found"}), 404


#8 UPDATE USER PROFILE WITH USER ID
@app.route('/user_profile/<int:user_id>', methods=['PUT'])
def update_user_profile_route(user_id):
    data = request.get_json()
    profile_data = data.get('profile')
    user = update_user_profile(user_id, profile_data['first_name'], profile_data['last_name'], profile_data['contact_no'], profile_data['dob'], profile_data['bio'], profile_data['country'])
    if user:
        return jsonify(user)
    else:
        return jsonify({"error": "User not found"}), 404


#9 DELETE USER WITH USER ID
@app.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user_route(user_id):
    try:
        user = delete_user_by_id(user_id)
        if user:
            return jsonify(user)
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete user", "details": str(e)}), 500
 

#10 UPLOAD PROFILE PICTURE
@app.route('/profile-picture/<int:user_id>', methods=['POST'])
def upload_image_route():
    user_id = request.form.get('user_id')
    image_file = request.files.get('image')
    if image_file:
        filename = secure_filename(image_file.filename)
        image_url = os.path.join('/static/images', filename)
        image_file.save(image_url)
        success = insert_image_to_db(user_id, image_url)
        if success:
            return jsonify({"message": "Image uploaded and database entry created"}), 200
        else:
            return jsonify({"error": "Failed to upload image and create database entry"}), 500
    else:
        return jsonify({"error": "No image file provided"}), 400
 

#11 CREATE A ROLE
@app.route('/role', methods=['POST'])
def create_role_route():
    data = request.get_json()
    role_name = data.get('role_name')
    description = data.get('description')
    role_id = create_role(role_name, description)
    return jsonify({'role_id': role_id, 'message': 'Role created successfully'}), 200
 

#12 READ ROLE BY ID
@app.route('/role/<int:role_id>', methods=['GET'])
def get_role_route(role_id):
    role = get_role_by_id(role_id)
    if role:
        return jsonify(role)
    return jsonify({'error': 'Role not found'}), 404
 

#13 UPDATE A ROLE
@app.route('/role/<int:role_id>', methods=['PUT'])
def update_role_route(role_id):
    data = request.get_json()
    role_name = data.get('role_name')
    description = data.get('description')
    try:
        update_role(role_id, role_name, description)
        return jsonify({"success": True, "message": "Role updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
 

#14 DELETE A ROLE
@app.route('/role/<int:role_id>', methods=['DELETE'])
def delete_role_route(role_id):
    try:
        success = delete_role_by_id(role_id)
        if success:
            return jsonify({"message": "Role deleted successfully"}), 200
        else:
            return jsonify({"error": "Role not found"}), 404
    except Exception as e:
        return jsonify({"error": "Failed to delete role", "details": str(e)}), 500


#15 READ ALL ROLES
@app.route('/roles', methods=['GET'])
def get_all_roles_route():
    roles = get_all_roles()
    return jsonify(roles)
 

#16 ADMIN TO DELETE USER
@app.route('/user_role/<int:user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user_role_route(user_id):
    data = request.get_json()
    role_name = data.get('role_name')
    try:
        deleted = delete_user_role(user_id, role_name, app.logger)
        if deleted:
            return jsonify({"message": f"Role {role_name} removed from user {user_id} successfully"}), 200
        else:
            return jsonify({"error": "Role not found or user does not have this role"}), 404
    except Exception as e:
        app.logger.error(f"Error deleting user role: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to delete user role", "details": str(e)}), 500


# #17 PAGINATION - GET USER DETAILS
# @app.route('/users', methods=['POST'])
# @jwt_required()
# @admin_required
# def users():
#     # GET DATA FROM REQUEST
#     "per_page" and "current_page" ###
#     offset = (current_page - 1) * per_page  # Formula to get OFFSET number
#     users = ### CALL get_user_details function by passing "per_page" and "offset"
#     parameters ###
#     return jsonify(users)

        
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1")