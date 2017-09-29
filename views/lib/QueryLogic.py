# -*- coding: UTF-8 -*-
import re


def mgo_text_split(query_text):
    ''' split text to support mongodb $text match on a phrase '''
    sep = r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?]'
    word_lst = re.split(sep, query_text)
    text_query = ' '.join('\"{}\"'.format(w) for w in word_lst)
    return text_query


# 搜索逻辑
def querylogic(list):
    query = {}
    if len(list) > 1 or len(list[0].split(':')) > 1:
        for _ in list:
            if _.find(':') > -1:
                q_key, q_value = _.split(':', 1)
                if q_key == 'port':
                    query['port'] = int(q_value)
                elif q_key == 'banner':
                    zhPattern = re.compile(u'[\u4e00-\u9fa5]+')
                    contents = q_value
                    match = zhPattern.search(contents)
                    # 如果没有中文用全文索引
                    if match:
                        query['banner'] = {"$regex": q_value, '$options': 'i'}
                    else:
                        text_query = mgo_text_split(q_value)
                        query['$text'] = {'$search': text_query, '$caseSensitive':True}
                elif q_key == 'ip':
                    query['ip'] = {"$regex": q_value}
                elif q_key == 'server':
                    query['server'] = q_value.lower()
                elif q_key == 'title':
                    query['webinfo.title'] = {"$regex": q_value, '$options': 'i'}
                elif q_key == 'tag':
                    query['webinfo.tag'] = q_value.lower()
                elif q_key == 'hostname':
                    query['hostname'] = {"$regex": q_value, '$options': 'i'}
                elif q_key == 'all':
                    filter_lst = []
                    for i in ('ip', 'banner', 'port', 'time', 'webinfo.tag', 'webinfo.title', 'server', 'hostname'):
                        filter_lst.append({i: {"$regex": q_value, '$options': 'i'}})
                    query['$or'] = filter_lst
                else:
                    query[q_key] = q_value
    else:
        filter_lst = []
        for i in ('ip', 'banner', 'port', 'time', 'webinfo.tag', 'webinfo.title', 'server', 'hostname'):
            filter_lst.append({i: {"$regex": list[0], '$options': 'i'}})
        query['$or'] = filter_lst
    return query
