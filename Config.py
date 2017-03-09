class Config(object):
    ACCOUNT = 'admin'
    PASSWORD = 'xunfeng321'


class ProductionConfig(Config):
    DB = '0.0.0.0'
    PORT = 65521
    DBUSERNAME = 'scan'
    DBPASSWORD = 'scanlol66'
    DBNAME = 'xunfeng'
