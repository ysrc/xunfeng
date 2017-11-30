#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import platform
import sys
from datetime import timedelta

from flask import Flask, redirect, render_template, request, session, url_for

from Config import ProductionConfig
from views.lib import Conn
from views.lib.Login import logincheck

app = Flask(__name__)
# 不搞随机数了，因为每次测试的时候，重启session都会失效，所以用这个
app.secret_key = platform.processor() + platform.node()
app.config.from_object(ProductionConfig)

Mongo = Conn.MongoDB(
		app.config.get('DB'),
		app.config.get('PORT'),
		app.config.get('DBNAME'),
		app.config.get('DBUSERNAME'),
		app.config.get('DBPASSWORD')
)

app.permanent_session_lifetime = timedelta(hours=6)
page_size = 60

sys.path.append(sys.path[0] + '/vulscan/vuldb/')
file_path = os.path.split(os.path.realpath(__file__))[0] + '/../vulscan/vuldb/'


@app.errorhandler(404)
def page_not_find(error):
	return render_template('404.html'), 404


@app.errorhandler(500)
def page_not_find(error):
	return render_template('500.html'), 500


@app.route('/login', methods=['get', 'post'])
def login():
	if request.method == 'GET':
		return render_template('login.html')
	else:
		account = request.form.get('account')
		password = request.form.get('password')
		if account == app.config.get('ACCOUNT') and password == app.config.get('PASSWORD'):
			session['login'] = 'loginsuccess'
			return redirect(url_for('search'))
		else:
			return redirect(url_for('login'))


@app.route('/loginout')
@logincheck
def login_out():
	session['login'] = ''
	return redirect(url_for('login'))
