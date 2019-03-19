# coding:utf-8
import urllib2
import thread
import time
import pymongo
import sys
import datetime
import hashlib
import json
import re
import uuid
import os
from kunpeng import kunpeng


sys.path.append(sys.path[0] + '/vuldb')
sys.path.append(sys.path[0] + "/../")

from config import ProductionConfig

db_conn = pymongo.MongoClient(ProductionConfig.DB, ProductionConfig.PORT)
na_db = getattr(db_conn, ProductionConfig.DBNAME)
na_db.authenticate(ProductionConfig.DBUSERNAME, ProductionConfig.DBPASSWORD)
na_task = na_db.Task
na_result = na_db.Result
na_plugin = na_db.Plugin
na_config = na_db.Config
na_heart = na_db.Heartbeat
na_update = na_db.Update
lock = thread.allocate()
PASSWORD_DIC = []
THREAD_COUNT = 50
TIMEOUT = 10
PLUGIN_DB = {}
TASK_DATE_DIC = {}
WHITE_LIST = []
kp = kunpeng()


class vulscan():
    def __init__(self, task_id, task_netloc, task_plugin):
        self.task_id = task_id
        self.task_netloc = task_netloc
        self.task_plugin = task_plugin
        self.result_info = ''
        self.start()

    def start(self):
        self.get_plugin_info()
        if '.json' in self.plugin_info['filename']:  # 标示符检测模式
            self.load_json_plugin()  # 读取漏洞标示
            self.set_request()  # 标示符转换为请求
            self.poc_check()  # 检测
        elif 'KP-' in self.plugin_info['filename']:
            self.log(str(self.task_netloc) + 'call kunpeng - ' + self.plugin_info['filename'])
            kp.set_config(TIMEOUT, PASSWORD_DIC)
            if self.task_netloc[1] != 80:
                self.result_info = kp.check('service', '{}:{}'.format(
                    self.task_netloc[0], self.task_netloc[1]), self.plugin_info['filename'])
            if not self.result_info:
                scheme = 'http'
                if self.task_netloc[1] == 443:
                    scheme = 'https'
                self.result_info = kp.check('web', '{}://{}:{}'.format(
                    scheme, self.task_netloc[0], self.task_netloc[1]), self.plugin_info['filename'])
        else:  # 脚本检测模式
            plugin_filename = self.plugin_info['filename']
            self.log(str(self.task_netloc) + 'call ' + self.task_plugin)
            if task_plugin not in PLUGIN_DB:
                plugin_res = __import__(plugin_filename)
                setattr(plugin_res, "PASSWORD_DIC", PASSWORD_DIC)  # 给插件声明密码字典
                PLUGIN_DB[plugin_filename] = plugin_res
            self.result_info = PLUGIN_DB[plugin_filename].check(
                str(self.task_netloc[0]), int(self.task_netloc[1]), TIMEOUT)
        self.save_request()  # 保存结果

    def get_plugin_info(self):
        info = na_plugin.find_one({"name": self.task_plugin})
        self.plugin_info = info

    def load_json_plugin(self):
        json_plugin = open(sys.path[0] + '/vuldb/' +
                           self.plugin_info['filename']).read()
        self.plugin_info['plugin'] = json.loads(json_plugin)['plugin']

    def set_request(self):
        url = 'http://' + \
            self.task_netloc[0] + ":" + \
            str(self.task_netloc[1]) + self.plugin_info['plugin']['url']
        if self.plugin_info['plugin']['method'] == 'GET':
            request = urllib2.Request(url)
        else:
            request = urllib2.Request(url, self.plugin_info['plugin']['data'])
        self.poc_request = request

    def get_code(self, header, html):
        try:
            m = re.search(r'<meta.*?charset=(.*?)"(>| |/)', html, flags=re.I)
            if m:
                return m.group(1).replace('"', '')
        except:
            pass
        try:
            if 'Content-Type' in header:
                Content_Type = header['Content-Type']
                m = re.search(r'.*?charset=(.*?)(;|$)',
                              Content_Type, flags=re.I)
                if m:
                    return m.group(1)
        except:
            pass

    def poc_check(self):
        try:
            res = urllib2.urlopen(self.poc_request, timeout=30)
            res_html = res.read(204800)
            header = res.headers
            # res_code = res.code
        except urllib2.HTTPError, e:
            # res_code = e.code
            header = e.headers
            res_html = e.read(204800)
        except Exception, e:
            return
        try:
            html_code = self.get_code(header, res_html).strip()
            if html_code and len(html_code) < 12:
                res_html = res_html.decode(html_code).encode('utf-8')
        except:
            pass
        an_type = self.plugin_info['plugin']['analyzing']
        vul_tag = self.plugin_info['plugin']['tag']
        analyzingdata = self.plugin_info['plugin']['analyzingdata']
        if an_type == 'keyword':
            # print poc['analyzingdata'].encode("utf-8")
            if analyzingdata.encode("utf-8") in res_html:
                self.result_info = vul_tag
        elif an_type == 'regex':
            if re.search(analyzingdata, res_html, re.I):
                self.result_info = vul_tag
        elif an_type == 'md5':
            md5 = hashlib.md5()
            md5.update(res_html)
            if md5.hexdigest() == analyzingdata:
                self.result_info = vul_tag

    def save_request(self):
        if self.result_info:
            time_ = datetime.datetime.now()
            self.log(str(self.task_netloc) + " " + self.result_info)
            v_count = na_result.find(
                {"ip": self.task_netloc[0], "port": self.task_netloc[1], "info": self.result_info}).count()
            if not v_count:
                na_plugin.update({"name": self.task_plugin},
                                 {"$inc": {'count': 1}})
            vulinfo = {"vul_name": self.plugin_info['name'], "vul_level": self.plugin_info['level'],
                       "vul_type": self.plugin_info['type']}
            w_vul = {"task_id": self.task_id, "ip": self.task_netloc[0], "port": self.task_netloc[1],
                     "vul_info": vulinfo, "info": self.result_info, "time": time_,
                     "task_date": TASK_DATE_DIC[str(self.task_id)]}
            na_result.insert(w_vul)
            # self.wx_send(w_vul)  # 自行定义漏洞提醒

    def log(self, info):
        lock.acquire()
        try:
            time_str = time.strftime('%X', time.localtime(time.time()))
            print "[%s] %s" % (time_str, info)
        except:
            pass
        lock.release()


def queue_get():
    global TASK_DATE_DIC
    task_req = na_task.find_and_modify(query={"status": 0, "plan": 0}, update={
                                       "$set": {"status": 1}}, sort={'time': 1})
    if task_req:
        TASK_DATE_DIC[str(task_req['_id'])] = datetime.datetime.now()
        return task_req['_id'], task_req['plan'], task_req['target'], task_req['plugin']
    else:
        task_req_row = na_task.find({"plan": {"$ne": 0}})
        if task_req_row:
            for task_req in task_req_row:
                if (datetime.datetime.now() - task_req['time']).days / int(task_req['plan']) >= int(task_req['status']):
                    if task_req['isupdate'] == 1:
                        task_req['target'] = update_target(
                            json.loads(task_req['query']))
                        na_task.update({"_id": task_req['_id']}, {
                                       "$set": {"target": task_req['target']}})
                    na_task.update({"_id": task_req['_id']}, {
                                   "$inc": {"status": 1}})
                    TASK_DATE_DIC[str(task_req['_id'])
                                  ] = datetime.datetime.now()
                    return task_req['_id'], task_req['plan'], task_req['target'], task_req['plugin']
        return '', '', '', ''


def update_target(query):
    target_list = []
    try:
        result_list = na_db.Info.find(query)
        for result in result_list:
            target = [result["ip"], result["port"]]
            target_list.append(target)
    except:
        pass
    return target_list


def monitor():
    global PASSWORD_DIC, THREAD_COUNT, TIMEOUT, WHITE_LIST
    while True:
        queue_count = na_task.find({"status": 0, "plan": 0}).count()
        if queue_count:
            load = 1
        else:
            ac_count = thread._count()
            load = float(ac_count - 6) / THREAD_COUNT
        if load > 1:
            load = 1
        if load < 0:
            load = 0
        na_heart.update({"name": "load"}, {
                        "$set": {"value": load, "up_time": datetime.datetime.now()}})
        PASSWORD_DIC, THREAD_COUNT, TIMEOUT, WHITE_LIST = get_config()
        if load > 0:
            time.sleep(8)
        else:
            time.sleep(60)


def get_config():
    try:
        config_info = na_config.find_one({"type": "vulscan"})
        pass_row = config_info['config']['Password_dic']
        thread_row = config_info['config']['Thread']
        timeout_row = config_info['config']['Timeout']
        white_row = config_info['config']['White_list']
        password_dic = pass_row['value'].split('\n')
        thread_count = int(thread_row['value'])
        timeout = int(timeout_row['value'])
        white_list = white_row['value'].split('\n')
        return password_dic, thread_count, timeout, white_list
    except Exception, e:
        print e

def install_kunpeng_plugin():
    time_ = datetime.datetime.now()
    for plugin in kp.get_plugin_list():
        level_list = ['严重','高危','中危','低危','提示']
        plugin_info = {
            '_id': plugin['references']['kpid'],
            'name': 'Kunpeng -' + plugin['name'],
            'info': plugin['remarks'] + ' ' + plugin['references']['cve'],
            'level': level_list[int(plugin['level'])],
            'type': plugin['type'],
            'author': plugin['author'],
            'url': plugin['references']['url'],
            'source': 1,
            'keyword': '',
            'add_time': time_,
            'filename': plugin['references']['kpid'],
            'count': 0
        }
        na_plugin.insert(plugin_info)

def init():
    time_ = datetime.datetime.now()
    if na_plugin.find().count() >= 1:
        return
    script_plugin = []
    json_plugin = []
    print 'init plugins'
    file_list = os.listdir(sys.path[0] + '/vuldb')
    for filename in file_list:
        try:
            if filename.split('.')[1] == 'py':
                script_plugin.append(filename.split('.')[0])
            if filename.split('.')[1] == 'json':
                json_plugin.append(filename)
        except:
            pass
    for plugin_name in script_plugin:
        try:
            res_tmp = __import__(plugin_name)
            plugin_info = res_tmp.get_plugin_info()
            plugin_info['add_time'] = time_
            plugin_info['filename'] = plugin_name
            plugin_info['count'] = 0
            na_plugin.insert(plugin_info)
        except:
            pass
    for plugin_name in json_plugin:
        try:
            json_text = open(sys.path[0] + '/vuldb/' + plugin_name, 'r').read()
            plugin_info = json.loads(json_text)
            plugin_info['add_time'] = time_
            plugin_info['filename'] = plugin_name
            plugin_info['count'] = 0
            del plugin_info['plugin']
            na_plugin.insert(plugin_info)
        except:
            pass
    install_kunpeng_plugin()


def kp_check():
    while True:
        try:
            new_release = kp.check_version()
            print new_release
            if new_release:
                info = new_release['body']
                if '###' in new_release['body']:
                    info = new_release['body'].split('###')[1]
                row = {
                    'info': info,
                    'isInstall': 0,
                    'name': new_release['name'],
                    'author': new_release['author']['login'],
                    'pushtime': new_release['published_at'],
                    'location': "",
                    'unicode': new_release['tag_name'],
                    'coverage': 0,
                    'source': 'kunpeng'
                }
                na_update.insert(row)
                time.sleep(60 * 60 * 48)
        except Exception as e:
            print e
        time.sleep(60 * 30)


def kp_update():
    while True:
        try:
            row = na_update.find_one_and_delete(
                {'source': 'kunpeng', 'isInstall': 1})
            if row:
                kp.update_version(row['unicode'])
                na_plugin.delete_many({'_id':re.compile('^KP')})
                install_kunpeng_plugin()
        except Exception as e:
            print e
        time.sleep(10)


if __name__ == '__main__':
    init()
    PASSWORD_DIC, THREAD_COUNT, TIMEOUT, WHITE_LIST = get_config()
    thread.start_new_thread(monitor, ())
    thread.start_new_thread(kp_check, ())
    thread.start_new_thread(kp_update, ())
    while True:
        try:
            task_id, task_plan, task_target, task_plugin = queue_get()
            if task_id == '':
                time.sleep(10)
                continue
            if PLUGIN_DB:
                del sys.modules[PLUGIN_DB.keys()[0]]  # 清理插件缓存
                PLUGIN_DB.clear()
            for task_netloc in task_target:
                while True:
                    if int(thread._count()) < THREAD_COUNT:
                        if task_netloc[0] in WHITE_LIST:
                            break
                        thread.start_new_thread(
                            vulscan, (task_id, task_netloc, task_plugin))
                        break
                    else:
                        time.sleep(2)
            if task_plan == 0:
                na_task.update({"_id": task_id}, {"$set": {"status": 2}})
        except Exception as e:
            print e
