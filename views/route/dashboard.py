# -*- coding: UTF-8 -*-

from datetime import datetime

from flask import render_template

from views import Mongo, app
from views.lib.Login import logincheck


# 统计页面
@app.route('/analysis')
@logincheck
def analysis():
	ip = len(Mongo.coll['Info'].distinct('ip'))
	record = Mongo.coll['Info'].find().count()
	task = Mongo.coll['Task'].find().count()
	vul = int(
			Mongo.coll['Plugin'].group([], {}, {'count': 0}, 'function(doc,prev){prev.count = prev.count + doc.count}')[
				0]['count'])
	plugin = Mongo.coll['Plugin'].find().count()
	vultype = Mongo.coll['Plugin'].group(['type'], {"count": {"$ne": 0}}, {'count': 0},
										 'function(doc,prev){prev.count = prev.count + doc.count}')
	cur = Mongo.coll['Statistics'].find().sort('date', -1).limit(30)
	trend = []
	for i in cur:
		trend.append(
				{'time': i['date'], 'add': i['info']['add'], 'update': i['info']['update'],
				 'delete': i['info']['delete']})
	vulbeat = Mongo.coll['Heartbeat'].find_one({'name': 'load'})
	scanbeat = Mongo.coll['Heartbeat'].find_one({'name': 'heartbeat'})
	if vulbeat == None or scanbeat == None:
		taskpercent = 0
		taskalive = False
		scanalive = False
	else:
		taskpercent = vulbeat['value'] * 100
		taskalive = (datetime.now() - vulbeat['up_time']).seconds
		scanalive = (datetime.now() - scanbeat['up_time']).seconds
		taskalive = True if taskalive < 120 else False
		scanalive = True if scanalive < 120 else False
	server_type = Mongo.coll['Info'].aggregate(
			[{'$group': {'_id': '$server', 'count': {'$sum': 1}}}, {'$sort': {'count': -1}}])
	web_type = Mongo.coll['Info'].aggregate([{'$match': {'server': 'web'}}, {'$unwind': '$webinfo.tag'},
											 {'$group': {'_id': '$webinfo.tag', 'count': {'$sum': 1}}},
											 {'$sort': {'count': -1}}])
	return render_template('analysis.html', ip=ip, record=record, task=task, vul=vul, plugin=plugin, vultype=vultype,
						   trend=sorted(trend, key=lambda x: x['time']), taskpercent=taskpercent, taskalive=taskalive,
						   scanalive=scanalive, server_type=server_type, web_type=web_type)
