import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:123456@localhost/ipfs_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False