# -*- coding: UTF-8 -*-

import json
import os
from datetime import datetime
from urllib import unquote, urlopen, urlretrieve, quote, urlencode
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import request, render_template, redirect, url_for, session, make_response
from lib.CreateExcel import *
from lib.Login import logincheck
from lib.AntiCSRF import anticsrf
from lib.QueryLogic import querylogic
from werkzeug.utils import secure_filename
from . import app, Mongo, page_size, file_path
import urllib2
import copy



# 搜索页
@app.route('/filter')
@logincheck
def Search():
    return render_template('search.html')


# 删除所有
@app.route('/deleteall', methods=['post'])
@logincheck
@anticsrf
def Deleteall():
    Mongo.coll['Task'].remove({})
    return 'success'


# 搜索结果页
@app.route('/')
@logincheck
def Main():
    q = request.args.get('q', '')
    page = int(request.args.get('page', '1'))
    plugin = Mongo.coll['Plugin'].find()  # 插件列表
    plugin_type = plugin.distinct('type')  # 插件类型列表
    if q:  # 基于搜索条件显示结果
        result = q.strip().split(';')
        query = querylogic(result)
        cursor = Mongo.coll['Info'].find(query).sort('time', -1).limit(page_size).skip((page - 1) * page_size)
        return render_template('main.html', item=cursor, plugin=plugin, itemcount=cursor.count(),
                               plugin_type=plugin_type)
    else:  # 自定义，无任何结果，用户手工添加
        return render_template('main.html', item=[], plugin=plugin, itemcount=0, plugin_type=plugin_type)


# 获取插件信息异步
@app.route('/getplugin', methods=['get', 'post'])
@logincheck
def Getplugin():
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


# 下载excel报表异步
@app.route('/downloadxls', methods=['get', 'post'])
@logincheck
@anticsrf
def DownloadXls():
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


# 插件列表页
@app.route('/plugin')
@logincheck
def Plugin():
    page = int(request.args.get('page', '1'))
    cursor = Mongo.coll['Plugin'].find().limit(page_size).skip((page - 1) * page_size)
    return render_template('plugin.html', cursor=cursor, vultype=cursor.distinct('type'), count=cursor.count())


# 新增插件异步
@app.route('/addplugin', methods=['get', 'post'])
@logincheck
@anticsrf
def AddPlugin():
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
                    file_name = file_name +'.py'

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
        code_tuple = open(file_path+file_name).read()
        code = ''
        for _ in code_tuple:
            code += _
        params = {'code': code}
        req = urllib2.Request('https://sec.ly.com/xunfeng/pluginupload')
        req.add_header('Content-Type','application/x-www-form-urlencoded')
        rsp = urllib2.urlopen(req,urlencode(params))
        print 'upload result:' + rsp.read()
    return result


# 删除插件异步
@app.route('/deleteplugin', methods=['get', 'post'])
@logincheck
@anticsrf
def DeletePlugin():
    oid = request.form.get('oid', '')
    if oid:
        result = Mongo.coll['Plugin'].find_one_and_delete({'_id': ObjectId(oid)}, remove=True)
        if not result['filename'].find('.') > -1:
            result['filename'] = result['filename'] + '.py'
        if os.path.exists(file_path + result['filename']):
            os.remove(file_path + result['filename'])
            return 'success'
    return 'fail'


# 统计页面
@app.route('/analysis')
@logincheck
def Analysis():
    ip = len(Mongo.coll['Info'].distinct('ip'))
    record = Mongo.coll['Info'].find().count()
    task = Mongo.coll['Task'].find().count()
    vul = int(Mongo.coll['Plugin'].group([], {}, {'count': 0},'function(doc,prev){prev.count = prev.count + doc.count}')[0]['count'])
    plugin = Mongo.coll['Plugin'].find().count()
    vultype = Mongo.coll['Plugin'].group(['type'], {"count":{"$ne":0}}, {'count': 0},'function(doc,prev){prev.count = prev.count + doc.count}')
    cur = Mongo.coll['Statistics'].find().sort('date', -1).limit(30)
    trend = []
    for i in cur:
        trend.append(
            {'time': i['date'], 'add': i['info']['add'], 'update': i['info']['update'], 'delete': i['info']['delete']})
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


# 配置页面
@app.route('/config')
@logincheck
def Config():
    val = []
    table = request.args.get('config', '')
    if table in ("vulscan", "nascan"):
        dict = Mongo.coll['Config'].find_one({'type': table})
        if dict and 'config' in dict:
            dict = dict['config']
            for _ in dict:
                if _.find('_') > 0:
                    item_type = "list"
                else:
                    item_type = "word"
                val.append({"show": item_type, "type": _, "info": dict[_]["info"], "help": dict[_]["help"],
                            "value": dict[_]["value"]})
    val = sorted(val, key=lambda x: x["show"], reverse=True)
    return render_template('config.html', values=val)


# 配置更新异步
@app.route('/updateconfig', methods=['get', 'post'])
@logincheck
@anticsrf
def UpdateConfig():
    rsp = 'fail'
    name = request.form.get('name', 'default')
    value = request.form.get('value', '')
    conftype = request.form.get('conftype', '')
    if name and value and conftype:
        if name == 'Masscan' or name == 'Port_list':
            origin_value = Mongo.coll['Config'].find_one({'type': 'nascan'})["config"][name]["value"]
            value = origin_value.split('|')[0] + '|' + value
        elif name == 'Port_list_Flag':
            name = 'Port_list'
            origin_value = Mongo.coll['Config'].find_one({'type': 'nascan'})["config"]['Port_list']["value"]
            value = value + '|' + origin_value.split('|')[1]
        elif name == 'Masscan_Flag':
            name = 'Masscan'
            path = Mongo.coll['Config'].find_one({'type': 'nascan'})["config"]["Masscan"]["value"]
            if len(path.split('|')) == 3:
                path = path.split('|')[1] + "|" + path.split('|')[2]
            else:
                path = path.split('|')[1]
            if value == '1':
                value = '1|' + path
            else:
                value = '0|' + path
        result = Mongo.coll['Config'].update({"type": conftype}, {'$set': {'config.' + name + '.value': value}})
        if result:
            rsp = 'success'
    return rsp


# 拉取线上最新插件异步
@app.route('/pullupdate')
@logincheck
@anticsrf
def PullUpdate():
    rsp = 'err'
    f = urlopen('https://sec.ly.com/xunfeng/getlist')
    j = f.read().strip()
    if j:
        try:
            remotelist = json.loads(j)
            #remotelist_temp = copy.deepcopy(remotelist)
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
def CheckUpdate():
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
def installplugin():
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


# 登录
@app.route('/login', methods=['get', 'post'])
def Login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        account = request.form.get('account')
        password = request.form.get('password')
        if account == app.config.get('ACCOUNT') and password == app.config.get('PASSWORD'):
            session['login'] = 'loginsuccess'
            return redirect(url_for('Search'))
        else:
            return redirect(url_for('Login'))


# 登出异步
@app.route('/loginout')
@logincheck
def LoginOut():
    session['login'] = ''
    return redirect(url_for('Login'))


@app.route('/404')
def NotFound():
    return render_template('404.html')


@app.route('/500')
def Error():
    return render_template('500.html')
