# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+mysqlconnector://username:password@host/dbname'
    SQLALCHEMY_TRACK_MODIFICATIONS = False