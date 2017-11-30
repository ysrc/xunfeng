# -*- coding: UTF-8 -*-

from datetime import datetime
from urllib import quote

from bson.objectid import ObjectId
from flask import make_response, redirect, request, url_for

from views import Mongo, app
from views.lib.AntiCSRF import anticsrf
from views.lib.CreateExcel import *
from views.lib.Login import logincheck
from views.lib.QueryLogic import querylogic


# 下载excel报表异步
@app.route('/downloadxls', methods=['get', 'post'])
@logincheck
@anticsrf
def xls_download():
	tid = request.args.get('taskid', '')
	taskdate = request.args.get('taskdate', '')
	result_list = []
	if tid:  # 有任务id
		if taskdate:  # 从任务中拉取指定批次扫描结果
			taskdate = datetime.strptime(taskdate, "%Y-%m-%d %H:%M:%S.%f")
			cursor = Mongo.coll['Result'].find({'task_id': ObjectId(tid), 'task_date': taskdate}).sort(
					'time', -1)
		else:  # 从任务中直接取该任务最新一次扫描结果
			lastscan = Mongo.coll["Result"].distinct('task_date', {'task_id': ObjectId(tid)})
			if len(lastscan) == 0:
				cursor = []
				taskdate = datetime.now()
			else:
				lastscan.sort(reverse=True)
				taskdate = lastscan[0]
				cursor = Mongo.coll['Result'].find({'task_id': ObjectId(tid), 'task_date': taskdate}).sort(
						'time', -1)
		title = Mongo.coll['Task'].find_one({'_id': ObjectId(tid)})['title']
		for _ in cursor:
			hostname = ''
			result = Mongo.coll['Info'].find_one({'ip': _['ip']})
			if result and 'hostname' in result:
				hostname = result['hostname']
			result_list.append(
					{'ip': _['ip'], 'port': _['port'], 'info': _['info'], 'vul_level': _['vul_info']['vul_level'],
					 'time': _['time'], 'vul_name': _['vul_info']['vul_name'], 'lastscan': taskdate, 'title': title,
					 'hostname': hostname})
		response = make_response(CreateTable(result_list, taskdate.strftime("%Y%m%d-%H%M%S")))
		if taskdate == '':
			response.headers["Content-Disposition"] = "attachment; filename=nodata.xls;"
		else:
			response.headers["Content-Disposition"] = "attachment; filename=" + quote(
					title.encode('utf-8')) + taskdate.strftime(
					"%Y-%m-%d-%H-%M-%S") + ".xls;"
	else:  # 下载综合报表
		tasks = Mongo.coll['Task'].find({})
		t_list = []
		for t in tasks:
			name = t['title']
			lastscan = Mongo.coll["Result"].distinct('task_date', {'task_id': t['_id']})
			if len(lastscan) == 0:
				cursor = Mongo.coll['Result'].find({'task_id': t['_id']})
				taskdate = None
			else:
				lastscan.sort(reverse=True)
				taskdate = lastscan[0]
				cursor = Mongo.coll['Result'].find({'task_id': t['_id'], 'task_date': taskdate})
			for _ in cursor:  # 单任务详情
				hostname = Mongo.coll['Info'].find_one({'ip': _['ip']})
				if hostname:
					_['hostname'] = hostname['hostname']
				else:
					_['hostname'] = None
				_['title'] = name
				_['vul_level'] = _['vul_info']['vul_level']
				_['vul_name'] = _['vul_info']['vul_name']
				_['lastscan'] = taskdate
				t_list.append(_)
		response = make_response(CreateTable(t_list, 'all_data'))
		response.headers["Content-Disposition"] = "attachment; filename=all_data.xls;"
	response.headers["Content-Type"] = "application/x-xls"
	return response


# 搜索结果报表下载接口
@app.route('/searchxls', methods=['get'])
@logincheck
@anticsrf
def xls_search_download():
	query = request.args.get('query', '')
	if query:
		result = query.strip().split(';')
		filter_ = querylogic(result)
		cursor = Mongo.coll['Info'].find(filter_).sort('time', -1)
		title_tup = ('IP', '端口号', '主机名', '服务类型')
		xls = [title_tup, ]
		for info in cursor:
			item = (
				info.get('ip'), info.get('port'),
				info.get('hostname'), info.get('server')
			)
			xls.append(item)
		file = write_data(xls, 'search_result')
		resp = make_response(file.getvalue())
		resp.headers["Content-Disposition"] = "attachment; filename=search_result.xls;"
		resp.headers["Content-Type"] = "application/x-xls"
		resp.headers["X-Content-Type-Options"] = "nosniff"
		return resp
	else:
		redirect(url_for('NotFound'))
