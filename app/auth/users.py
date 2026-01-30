import json
from flask_jwt_extended import create_access_token
from secrets import token_urlsafe
from dotenv import load_dotenv
from flask import jsonify, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from .__init__ import users_bp
import os
import redis

load_dotenv()

password = os.environ.get('REDIS_PASSWORD')

r = redis.Redis(
    host='redis-18252.c275.us-east-1-4.ec2.cloud.redislabs.com',
    port=18252,
    decode_responses=True,
    username='default',
    password=password
)



@users_bp.post('/register')
def register():
    data = request.json
    email = data['email']
    first_name = data['first_name']
    last_name = data['last_name']
    password = data['password']

    if r.hexists('emails_to_tokens', email):
        return jsonify({'message': 'Email already exists!'}), 400

    usertoken = token_urlsafe(32)
    hashed_password = generate_password_hash(password)

    user_schema = {
        'hashed_password': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'usertoken': usertoken 
    }

    user_data = json.dumps(user_schema)

    r.hset('users', usertoken, user_data)

    r.hset('emails_to_tokens', email, usertoken)

    return jsonify({'message': 'User registered successfully!', 'usertoken': usertoken}), 200


@users_bp.post('/login')
def login():
    data = request.json
    email = data['email']
    password = data['password']

    usertoken = r.hget('emails_to_tokens', email)
    if not usertoken:
        return jsonify({'message': 'Invalid email or password!'}), 401

    user_data = r.hget('users', usertoken)
    if user_data:
        user_schema = json.loads(user_data)
        hashed_password = user_schema['hashed_password']
        if check_password_hash(hashed_password, password):
            
            access_token = create_access_token(identity=usertoken)
            return jsonify(access_token=access_token, email=email,usertoken=usertoken), 200

    return jsonify({'message': 'Invalid email or password!'}), 401




@users_bp.post('/handle_user_ingredient_list')
def handle_user_ingredient_list():
    data = request.json
    usertoken = data.get('usertoken')
    name = data.get('name')
    id = data.get('id')

    if not all([usertoken, name, id]):
        return jsonify({'error': 'Missing required data'}), 400

    pantry_key = f"pantry:{usertoken}"  
    ingredient_field = f"{name}:{id}"  
    try:
        if r.hexists(pantry_key, ingredient_field):
            # If the ingredient exists, remove it
            r.hdel(pantry_key, ingredient_field)
            action = 'deleted'
        else:
            # If the ingredient does not exist, add it
            r.hset(pantry_key, ingredient_field, 'true')  # Value 'true' is arbitrary
            action = 'added'

        return jsonify({'message': f'Ingredient {action} successfully'}), 200
    except Exception as e:
        print(f"Error handling user ingredient list: {e}")
        return jsonify({'error': 'An error occurred processing your request'}), 500



@users_bp.get('/get_user_pantry_items')
def get_user_pantry_items():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Authorization token is missing!'}), 401
    
    usertoken = auth_header.split(" ")[1]

    # This checks if the user exists which might not be necessary if you're only fetching from the pantry
    # Consider removing if you don't store user data in 'users' or if it's not necessary for this operation
    user_data = r.hget('users', usertoken)
    if not user_data:
        return jsonify({'message': 'Invalid or expired usertoken!'}), 401

    pantry_key = f"pantry:{usertoken}"
    pantry_items = []

    # Fetch all ingredients from the user's pantry hash
    items = r.hgetall(pantry_key)
    for item_key, _ in items.items():  # The value is ignored, assuming it's just a placeholder
        # Assuming item_key is in the format 'name:id'
        name, item_id = item_key.split(':')
        pantry_items.append({'name': name, 'id': item_id})

    return jsonify(pantry_items), 200

