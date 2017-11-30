# -*- coding: UTF-8 -*-

import json
import os
import urllib2
from datetime import datetime
from urllib import unquote, urlencode, urlopen, urlretrieve

from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import render_template, request
from werkzeug.utils import secure_filename

from views import Mongo, app, file_path, page_size
from views.lib.AntiCSRF import anticsrf
from views.lib.Login import logincheck


# 插件列表页
@app.route('/plugin')
@logincheck
def plugin_list():
	page = int(request.args.get('page', '1'))
	cursor = Mongo.coll['Plugin'].find().limit(page_size).skip((page - 1) * page_size)
	return render_template('plugin.html', cursor=cursor, vultype=cursor.distinct('type'), count=cursor.count())


# 新增插件异步
@app.route('/addplugin', methods=['get', 'post'])
@logincheck
@anticsrf
def plug_add():
	result = 'fail'
	f = request.files['file']
	isupload = request.form.get('isupload', 'false')
	file_name = ''
	if f:
		fname = secure_filename(f.filename)
		if fname.split('.')[-1] == 'py':
			path = file_path + fname
			if os.path.exists(file_path + fname):
				fname = fname.split('.')[0] + '_' + str(datetime.now().second) + '.py'
				path = file_path + fname
			f.save(path)
			if os.path.exists(path):
				file_name = fname.split('.')[0]
				module = __import__(file_name)
				mark_json = module.get_plugin_info()
				mark_json['filename'] = file_name
				mark_json['add_time'] = datetime.now()
				mark_json['count'] = 0
				if 'source' not in mark_json:
					mark_json['source'] = 0
				insert_result = Mongo.coll['Plugin'].insert(mark_json)
				if insert_result:
					result = 'success'
					file_name = file_name + '.py'
	
	else:
		name = request.form.get('name', '')
		info = request.form.get('info', '')
		author = request.form.get('author', '')
		level = request.form.get('level', '')
		type = request.form.get('vultype', '')
		keyword = request.form.get('keyword', '')
		pluginurl = request.form.get('pluginurl', '')
		methodurl = request.form.get('methodurl', '')
		pdata = request.form.get('pdata', '')
		analyzing = request.form.get('analyzing', '')
		analyzingdata = request.form.get('analyzingdata', '')
		tag = request.form.get('tag', '')
		try:
			query = {'name': name, 'info': info, 'level': level, 'type': type, 'author': author, 'url': pluginurl,
					 'keyword': keyword, 'source': 0}
			query['plugin'] = {'method': methodurl.split(' ', 1)[0], 'url': methodurl.split(' ', 1)[1],
							   'analyzing': analyzing, 'analyzingdata': analyzingdata, 'data': pdata, 'tag': tag}
			file_name = secure_filename(name) + '_' + str(datetime.now().second) + ".json"
			with open(file_path + file_name, 'wb') as wt:
				wt.writelines(json.dumps(query))
			query.pop('plugin')
			query['add_time'] = datetime.now()
			query['count'] = 0
			query['filename'] = file_name
			insert_result = Mongo.coll['Plugin'].insert(query)
			if insert_result:
				result = 'success'
		except:
			pass
	if isupload == 'true' and result == 'success':
		code_tuple = open(file_path + file_name).read()
		code = ''
		for _ in code_tuple:
			code += _
		params = {'code': code}
		req = urllib2.Request('https://sec.ly.com/xunfeng/pluginupload')
		req.add_header('Content-Type', 'application/x-www-form-urlencoded')
		rsp = urllib2.urlopen(req, urlencode(params))
		print 'upload result:' + rsp.read()
	return result


# 拉取线上最新插件异步
@app.route('/pullupdate')
@logincheck
@anticsrf
def plug_update():
	rsp = 'err'
	f = urlopen('https://sec.ly.com/xunfeng/getlist')
	j = f.read().strip()
	if j:
		try:
			remotelist = json.loads(j)
			# remotelist_temp = copy.deepcopy(remotelist)
			plugin = Mongo.coll['Plugin'].find({'source': 1})
			for p in plugin:
				for remote in remotelist:
					if p['name'] == remote['name'] and remote['coverage'] == 0:
						remotelist.remove(remote)
			locallist = Mongo.coll['Update'].aggregate([{'$project': {'_id': 0, 'unicode': 1}}])
			local = []
			for i in locallist:
				local.append(i['unicode'])
			ret = [i for i in remotelist if i['unicode'] not in local]
			for i in ret:
				i['isInstall'] = 0
				Mongo.coll['Update'].insert(i)
			rsp = 'true'
		except:
			pass
	return rsp


# 检查本地已知的线上插件列表异步
@app.route('/checkupdate')
@logincheck
@anticsrf
def plug_check():
	json = []
	notinstall = Mongo.coll['Update'].find({'isInstall': 0}).sort('unicode', -1)
	for _ in notinstall:
		json.append({'unicode': _['unicode'], 'name': _['name'], 'info': _['info'], 'time': _['pushtime'],
					 'author': _['author']})
	return dumps(json)


# 安装／下载插件异步
@app.route('/installplugin')
@logincheck
@anticsrf
def plug_install():
	rsp = 'fail'
	unicode = request.args.get('unicode', '')
	item = Mongo.coll['Update'].find_one({'unicode': unicode})
	json_string = {'add_time': datetime.now(), 'count': 0, 'source': 1}
	file_name = secure_filename(item['location'].split('/')[-1])
	if os.path.exists(file_path + file_name):
		if ".py" in file_name:
			db_record = Mongo.coll['Plugin'].find_one({'filename': file_name.split('.')[0]})
		else:
			db_record = Mongo.coll['Plugin'].find_one({'filename': file_name})
		if not db_record or not db_record['source'] == 1:
			file_name = file_name.split('.')[0] + '_' + str(datetime.now().second) + '.' + \
						file_name.split('.')[-1]
		else:
			db_record = Mongo.coll['Plugin'].delete_one({'filename': file_name.split('.')[0]})
	if item['location'].find('/') == -1:
		urlretrieve('https://sec.ly.com/xunfeng/getplugin?name=' + item['location'], file_path + file_name)
	else:
		urlretrieve(item['location'], file_path + file_name)  # 兼容旧的插件源
	if os.path.exists(file_path + file_name):
		try:
			if file_name.split('.')[-1] == 'py':
				module = __import__(file_name.split('.')[0])
				mark_json = module.get_plugin_info()
				json_string['filename'] = file_name.split('.')[0]
			else:
				json_text = open(file_path + file_name, 'r').read()
				mark_json = json.loads(json_text)
				json_string['filename'] = file_name
				mark_json.pop('plugin')
			json_string.update(mark_json)
			Mongo.coll['Plugin'].insert(json_string)
			Mongo.coll['Update'].update_one({'unicode': unicode}, {'$set': {'isInstall': 1}})
			rsp = 'success'
		except:
			pass
	return rsp


# 删除插件异步
@app.route('/deleteplugin', methods=['get', 'post'])
@logincheck
@anticsrf
def plug_delete():
	oid = request.form.get('oid', '')
	if oid:
		result = Mongo.coll['Plugin'].find_one_and_delete({'_id': ObjectId(oid)}, remove=True)
		if not result['filename'].find('.') > -1:
			result['filename'] = result['filename'] + '.py'
		if os.path.exists(file_path + result['filename']):
			os.remove(file_path + result['filename'])
			return 'success'
	return 'fail'


# 获取插件信息异步
@app.route('/getplugin', methods=['get', 'post'])
@logincheck
def plug_get():
	type = request.form.get('type', '')
	risk = request.form.get('risk', '')
	search = request.form.get('search', '')
	query = {}
	if type:
		query['type'] = type
	if risk:
		query['level'] = risk
	if search:
		search = unquote(search)
		query['name'] = {"$regex": search, '$options': 'i'}
	cursor = Mongo.coll['Plugin'].find(query)
	rsp = []
	for i in cursor:
		result = {'name': i['name'], 'info': i['info']}
		rsp.append(result)
	return json.dumps(rsp)
