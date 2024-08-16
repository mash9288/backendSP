import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_default_secret_key'
    # Example MySQL connection string
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://user:password@http://localhost:3306/mydatabase'
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sql12706904:x1a5GLpNBy@sql12.freemysqlhosting.net:3306/sql12706904'
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sql12717900:XfKeetRZEc@sql12.freemysqlhosting.net:3306/sql12717900'
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sql5717901:CrPsJv3Vmr@sql5.freemysqlhosting.net:3306/sql5717901'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sql8717902:s87lHMshd4@sql8.freemysqlhosting.net:3306/sql8717902'


    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://sql8717902:s87lHMshd4@sql8.freemysqlhosting.net:3306/sql8717902'
    # SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://kimhoe.gcit:P06coqOWytAT@ep-little-hall-a1ykg9bf.ap-southeast-1.aws.neon.tech/usmdb'
    
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'a_default_jwt_secret_key'

    
class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True


class TestingConfig(Config):
    TESTING = True
    # SQLALCHEMY_DATABASE_URI = 'postgresql://kimhoe.gcit:P06coqOWytAT@ep-little-hall-a1ykg9bf.ap-southeast-1.aws.neon.tech/usmdb'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sql8717902:s87lHMshd4@sql8.freemysqlhosting.net:3306/sql8717902'

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_ECHO = False
