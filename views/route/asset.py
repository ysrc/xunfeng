# -*- coding: UTF-8 -*-

from flask import render_template, request

from views import Mongo, app, page_size
from views.lib.Login import logincheck
from views.lib.QueryLogic import querylogic


# 搜索页
@app.route('/filter')
@logincheck
def search():
	return render_template('search.html')


# 搜索结果页
@app.route('/')
@logincheck
def main():
	q = request.args.get('q', '')
	page = int(request.args.get('page', '1'))
	plugin = Mongo.coll['Plugin'].find()  # 插件列表
	plugin_type = plugin.distinct('type')  # 插件类型列表
	if q:  # 基于搜索条件显示结果
		result = q.strip().split(';')
		query = querylogic(result)
		cursor = Mongo.coll['Info'].find(query).sort('time', -1).limit(page_size).skip((page - 1) * page_size)
		return render_template('main.html', item=cursor, plugin=plugin, itemcount=cursor.count(),
							   plugin_type=plugin_type, query=q)
	else:  # 自定义，无任何结果，用户手工添加
		return render_template('main.html', item=[], plugin=plugin, itemcount=0, plugin_type=plugin_type)
