# -*- coding: UTF-8 -*-
import re


# 搜索逻辑
def querylogic(list):
    query = {}
    if len(list) > 1 or len(list[0].split(':')) > 1:
        for _ in list:
            if _.find(':') > -1:
                if _.split(':')[0] == 'port':
                    query['port'] = int(_.split(':')[1])
                elif _.split(':')[0] == 'banner':
                    zhPattern = re.compile(u'[\u4e00-\u9fa5]+')
                    contents = _.split(':')[1]
                    match = zhPattern.search(contents)
                    # 如果没有中文用全文索引
                    if match:
                        query['banner'] = {"$regex": _.split(':')[1], '$options': 'i'}
                    else:
                        query['$text'] = {'$search': _.split(':')[1]}
                elif _.split(':')[0] == 'ip':
                    ip = _.split(':')[1]
                    query['ip'] = {"$regex": ip}
                elif _.split(':')[0] == 'server':
                    query['server'] = _.split(':')[1].lower()
                elif _.split(':')[0] == 'title':
                    query['webinfo.title'] = {"$regex": _.split(':')[1], '$options': 'i'}
                elif _.split(':')[0] == 'tag':
                    query['webinfo.tag'] = _.split(':')[1].lower()
                elif _.split(':')[0] == 'hostname':
                    query['hostname'] = {"$regex": _.split(':')[1], '$options': 'i'}
                elif _.split(':')[0] == 'all':
                    filter = []
                    for i in ('ip', 'banner', 'port', 'time', 'webinfo.tag', 'webinfo.title', 'server', 'hostname'):
                        filter.append({i: {"$regex": _.split(':')[1], '$options': 'i'}})
                    query['$or'] = filter
                else:
                    query[_.split(':')[0]] = _.split(':')[1]
    else:
        filter = []
        for i in ('ip', 'banner', 'port', 'time', 'webinfo.tag', 'webinfo.title', 'server', 'hostname'):
            filter.append({i: {"$regex": list[0], '$options': 'i'}})
        query['$or'] = filter
    return query
