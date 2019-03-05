import pymongo
import sys
import os
sys.path.append(os.path.split(os.path.realpath(__file__))[0]+"/../../")
from config import ProductionConfig
db_conn = pymongo.MongoClient(ProductionConfig.DB, ProductionConfig.PORT)
na_db = getattr(db_conn, ProductionConfig.DBNAME)
na_db.authenticate(ProductionConfig.DBUSERNAME, ProductionConfig.DBPASSWORD)
NA_INFO = na_db.Info
NA_HISTORY = na_db.History