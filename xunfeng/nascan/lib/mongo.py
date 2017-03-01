import sys
import os

import pymongo

from xunfeng.core.Config import ProductionConfig


db_conn = pymongo.MongoClient(ProductionConfig.DB, ProductionConfig.PORT)
na_db = getattr(db_conn, ProductionConfig.DBNAME)
na_db.authenticate(ProductionConfig.DBUSERNAME, ProductionConfig.DBPASSWORD)
NA_INFO = na_db.Info
NA_HISTORY = na_db.History