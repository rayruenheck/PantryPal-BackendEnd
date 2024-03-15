import json
from secrets import token_urlsafe
from dotenv import load_dotenv
from flask import jsonify, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from .__init import users_bp
import os
import redis

load_dotenv()

password = os.environ.get('REDIS_PASSWORD')




r = redis.Redis(
  host='redis-10244.c323.us-east-1-2.ec2.cloud.redislabs.com',
  port=10244,
  password=password)



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

    
    usertoken = usertoken.decode('utf-8')
    

    user_data = r.hget('users', usertoken)
    if user_data:
        user_schema = json.loads(user_data.decode('utf-8'))
        hashed_password = user_schema['hashed_password']
        if check_password_hash(hashed_password, password):
            session['user'] = usertoken  # Store usertoken in the session
            response = {'usertoken': usertoken, 'email': email, 'name': f"{user_schema['first_name']} {user_schema['last_name']}"}
            return jsonify(response), 200

    return jsonify({'message': 'Invalid email or password!'}), 401




@users_bp.post('/handle_user_ingredient_list')
def handle_user_ingredient_list():
    data = request.json
    usertoken = data.get('usertoken')
    name = data.get('name')
    id = data.get('id')

    if not all([usertoken, name, id]):
        return jsonify({'error': 'Missing required data'}), 400

    try:
        key = f"{usertoken}:{name}"
        if r.hexists('pantries', key):
            r.hdel('pantries', key)
            action = 'deleted'
        else:
            r.hset('pantries', key, id)
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

    
    user_data = r.hget('users', usertoken)
    if not user_data:
        return jsonify({'message': 'Invalid or expired usertoken!'}), 401

    pantry_key_pattern = f"{usertoken}:*"
    pantry_items = []
    for key in r.scan_iter(match=pantry_key_pattern):
        item_id = r.hget('pantries', key.decode('utf-8'))
        if item_id:
            item_name = key.decode('utf-8').split(':')[1] 
            pantry_items.append({'name': item_name, 'id': item_id.decode('utf-8')})

    return jsonify(pantry_items), 200


