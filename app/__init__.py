from flask import Flask
import os
from flask_cors import CORS
from app.auth.users import users_bp
from flask_jwt_extended import JWTManager

app = Flask(__name__)



app.config['JWT_SECRET_KEY'] = os.urandom(12).hex()

CORS(app, supports_credentials=True)

jwt = JWTManager(app)

app.secret_key = os.urandom(24)

app.register_blueprint(users_bp)

if __name__ == '__main__':
    app.run(debug=True)