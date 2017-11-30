class Config(object):
    ACCOUNT = 'admin'
    PASSWORD = 'xunfeng321'


class ProductionConfig(Config):
    DB = '127.0.0.1'
    PORT = 27017
    DBUSERNAME = 'xunfeng'
    DBPASSWORD = 'xunfeng'
    DBNAME = 'xunfeng'
