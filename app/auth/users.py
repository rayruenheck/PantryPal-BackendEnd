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
    usertoken = token_urlsafe(32)
    if r.hexists('users', email):
        return jsonify({'message': 'Email already exists!'}), 400
    hashed_password = generate_password_hash(password)

    user_schema = {
        'hashed_password': hashed_password,
        'first_name': first_name,
        'last_name' : last_name,
        'usertoken': usertoken
    }

    user_data = json.dumps(user_schema)

    r.hset('users', email, user_data)
    return jsonify({'message': 'User registered successfully!'}), 200

@users_bp.post('/login')
def login():
    data = request.json
    email = data['email']
    password = data['password']

    user_data = r.hget('users', email)

    if user_data:
        user_schema = json.loads(user_data.decode('utf-8'))
        hashed_password = user_schema['hashed_password']
        if check_password_hash(hashed_password, password):
            session['user'] = email
            response = {'usertoken': user_schema['usertoken'], 'email' : email, 'name' : f"{user_schema['first_name']} {user_schema['last_name']}"}
            return response, 200
        
    return jsonify({'message': 'Invalid email or password!'}), 401