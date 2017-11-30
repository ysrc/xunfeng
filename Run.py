#! /usr/bin/env python
# -*- coding: utf-8 -*-

from views import app
from views.route.asset import *
from views.route.config import *
from views.route.dashboard import *
from views.route.plug import *
from views.route.report import *
from views.route.task import *
"""
	TIPS:
	
	80 port 启动需要root权限
	如果提示 socket.error: [Errno 13] Permission denied
	则可用两种方法解决
		1，使用sudo启动
		2，或者改端口为8000
	在浏览器中需要使用 http://localhost:80/
"""
if __name__ == '__main__':
	# app.debug = True
	app.run(threaded=True, port=8000, host='0.0.0.0')
