# -*- coding: UTF-8 -*-

from functools import wraps

from flask import redirect, session, url_for


# 登录状态检查
def logincheck(f):
	@wraps(f)
	def wrapper(*args, **kwargs):
		if session.has_key('login'):
			if session['login'] == 'loginsuccess':
				return f(*args, **kwargs)
			else:
				return redirect(url_for('login'))
		else:
			return redirect(url_for('login'))
	
	return wrapper
