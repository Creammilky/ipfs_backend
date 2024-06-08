import os

class Config:
    # 必须改成你自己的数据库用户和密码（密码中不可以有\ /字符）
    # 必须先创建ipfs_db，使用create database ipfs_db;指令
    # 在命令行中src目录下分别执行 flask db init (如果src中没有migration文件夹的话) 和 flask db migrate 和 flask db upgrade接口完成数据库迁移
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:123456@localhost/ipfs_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False