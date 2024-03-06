import os

class Config:
    JWT_SECRET_KEY = os.urandom(12).hex()