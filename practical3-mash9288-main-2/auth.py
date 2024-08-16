# from functools import wraps
# from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request
# from flask import jsonify
 
# def admin_required(fn):
#     @wraps(fn)
#     def wrapper(*args, **kwargs):
#         # Ensure the JWT is present and valid
#         verify_jwt_in_request()
#         # Assuming the identity is the user ID
#         current_user = get_jwt_identity()
 
#         # Retrieve the user role from JWT claims
#         user_role = get_user_role_from_jwt()
#         print('role:' + user_role)  # Consider replacing this with secure logging in production
 
#         if user_role != 'admin':
#             return jsonify({"msg": "Administration privileges required."}), 403
            
#         return fn(*args, **kwargs)
#     return wrapper
 
# def get_user_role_from_jwt():
#     claims = get_jwt()
#     return claims['role'] if 'role' in claims else None


from functools import wraps
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request
from flask import jsonify
import jwt
import datetime

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Encode a JWT for testing or demonstration purposes
        encoded_jwt = jwt.encode({'some': 'payload', 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)}, 'secret', algorithm='HS256')
        print("Encoded JWT:", encoded_jwt)

        # Ensure the JWT is present and valid
        verify_jwt_in_request()

        # Decode the JWT to simulate getting the payload without verifying it against a request
        decoded_jwt = jwt.decode(encoded_jwt, 'secret', algorithms=['HS256'])
        print("Decoded JWT:", decoded_jwt)

        # Assuming the identity is the user ID
        current_user = get_jwt_identity()

        # Retrieve the user role from JWT claims
        user_role = get_user_role_from_jwt()

        if user_role != 'admin':
            return jsonify({"msg": "Administration privileges required."}), 403

        return fn(*args, **kwargs)
    return wrapper

def get_user_role_from_jwt():
    claims = get_jwt()
    return claims['role'] if 'role' in claims else None