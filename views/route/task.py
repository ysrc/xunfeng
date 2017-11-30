# -*- coding: UTF-8 -*-

from datetime import datetime
from urllib import unquote

from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import render_template, request

from views import Mongo, app, page_size
from views.lib.AntiCSRF import anticsrf
from views.lib.Login import logincheck
from views.lib.QueryLogic import querylogic


# 新增任务异步
@app.route('/addtask', methods=['get', 'post'])
@logincheck
@anticsrf
def Addtask():
	title = request.form.get('title', '')
	plugin = request.form.get('plugin', '')
	condition = unquote(request.form.get('condition', ''))
	plan = request.form.get('plan', 0)
	ids = request.form.get('ids', '')
	isupdate = request.form.get('isupdate', '0')
	resultcheck = request.form.get('resultcheck', '0')
	result = 'fail'
	if plugin:
		targets = []
		if resultcheck == 'true':  # 结果集全选
			list = condition.strip().split(';')
			query = querylogic(list)
			cursor = Mongo.coll['Info'].find(query)
			for i in cursor:
				tar = [i['ip'], i['port']]
				targets.append(tar)
		else:  # 当前页结果选择
			for i in ids.split(','):
				tar = [i.split(':')[0], int(i.split(':')[1])]
				targets.append(tar)
		temp_result = True
		for p in plugin.split(','):
			query = querylogic(condition.strip().split(';'))
			item = {'status': 0, 'title': title, 'plugin': p, 'condition': condition, 'time': datetime.now(),
					'target': targets, 'plan': int(plan), 'isupdate': int(isupdate), 'query': dumps(query)}
			insert_reuslt = Mongo.coll['Task'].insert(item)
			if not insert_reuslt:
				temp_result = False
		if temp_result:
			result = 'success'
	return result


# 任务列表页面
@app.route('/task')
@logincheck
def Task():
	page = int(request.args.get('page', '1'))
	cursor = Mongo.coll['Task'].find().sort('time', -1).limit(page_size).skip((page - 1) * page_size)
	return render_template('task.html', item=cursor)


# 复测任务异步
@app.route('/taskrecheck')
@logincheck
@anticsrf
def Recheck():
	tid = request.args.get('taskid', '')
	task = Mongo.coll['Task'].find_one({'_id': ObjectId(tid)})
	result = 'fail'
	if task and task['plan'] == 0 and task['status'] == 2:  # 一次性任务，并且已经扫描完成
		result = Mongo.coll['Task'].update({'_id': ObjectId(tid)}, {'$set': {'status': 0}})
		if result:
			result = 'success'
	return result


# 任务详情页面
@app.route('/taskdetail')
@logincheck
def TaskDetail():
	id = request.args.get('taskid', '')
	page = int(request.args.get('page', '1'))
	taskdate = request.args.get('taskdate', "")
	plugin_name = ''
	task_info = Mongo.coll['Task'].find_one({'_id': ObjectId(id)})
	if task_info:
		plugin_name = task_info['plugin']
	vulcount = 0
	lastscan = Mongo.coll["Result"].distinct('task_date', {'task_id': ObjectId(id)})
	result_list = []
	if len(lastscan) > 0:
		lastscan.sort(reverse=True)
		if taskdate:  # 根据扫描批次查看结果
			cursor = Mongo.coll['Result'].find(
					{'task_id': ObjectId(id), 'task_date': datetime.strptime(taskdate, "%Y-%m-%d %H:%M:%S.%f")}).sort(
					'time', -1).limit(page_size).skip((page - 1) * page_size)
		else:  # 查看最新批次结果
			taskdate = lastscan[0].strftime("%Y-%m-%d %H:%M:%S.%f")
			cursor = Mongo.coll['Result'].find(
					{'task_id': ObjectId(id), 'task_date': lastscan[0]}).sort('time', -1).limit(page_size).skip(
					(page - 1) * page_size)
		vulcount = cursor.count()
		for _ in cursor:
			result_list.append(
					{'ip': _['ip'], 'port': _['port'], 'info': _['info'], 'vul_level': _['vul_info']['vul_level'],
					 'time': _['time']})
		
		# 速度优化，数据量多采取不同的方式查询
		if len(result_list) > 100:
			ip_hostname = {}
			hostname = Mongo.coll['Info'].aggregate(
					[{'$match': {'hostname': {'$ne': None}}}, {'$project': {'_id': 0, 'ip': 1, 'hostname': 1}}])
			for _ in hostname:
				if 'hostname' in hostname:
					ip_hostname[_["ip"]] = _["hostname"]
			for _ in result_list:
				if 'ip' in ip_hostname:
					_['hostname'] = ip_hostname[_["ip"]]
				else:
					_['hostname'] = ''
		else:
			for _ in result_list:
				hostname = Mongo.coll['Info'].find_one({'ip': _['ip']})
				if hostname and 'hostname' in hostname:
					_['hostname'] = hostname['hostname']
				else:
					_['hostname'] = ''
	return render_template('detail.html', item=result_list, count=vulcount, id=id, taskdate=taskdate,
						   plugin_name=plugin_name, scanlist=lastscan)


# 删除任务异步
@app.route('/deletetask', methods=['get', 'post'])
@logincheck
@anticsrf
def DeleteTask():
	oid = request.form.get('oid', '')
	if oid:
		result = Mongo.coll['Task'].delete_one({'_id': ObjectId(oid)})
		if result.deleted_count > 0:
			result = Mongo.coll['Result'].delete_many({'task_id': ObjectId(oid)})
			if result:
				return 'success'
	return 'fail'


# 删除所有
@app.route('/deleteall', methods=['post'])
@logincheck
@anticsrf
def Deleteall():
	Mongo.coll['Task'].remove({})
	return 'success'
