# coding: utf-8

import os

# FIXME Windows下中文路径可能会出现问题
ROOT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IS_DEBUG = True

PAGE_SIZE = 60


class Config(object):
    ACCOUNT = 'admin'
    PASSWORD = 'xunfeng321'


class ProductionConfig(Config):
    DB = '127.0.0.1'
    PORT = 65521
    DBUSERNAME = 'scan'
    DBPASSWORD = 'scanlol66'
    DBNAME = 'xunfeng'
