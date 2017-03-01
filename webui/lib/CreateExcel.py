# -*- coding: UTF-8 -*-

import xlwt
import StringIO


# 将数据保存成excel
def write_data(data, tname):
    file = xlwt.Workbook(encoding='utf-8')
    table = file.add_sheet(tname, cell_overwrite_ok=True)
    l = 0
    for line in data:
        c = 0
        for _ in line:
            table.write(l, c, line[c])
            c += 1
        l += 1
    sio = StringIO.StringIO()
    file.save(sio)
    return sio


# excel业务逻辑处理
def CreateTable(cursor, id):
    item = []
    item.append(['IP', '端口', '主机名', '风险等级', '漏洞描述', '插件类型', '任务名称', '时间', '扫描批次'])
    for i in cursor:
        if i['lastscan']:
            _ = [i['ip'], i['port'], i['hostname'], i['vul_level'], i['info'],
                 i['vul_name'], i['title'], i['time'].strftime('%Y-%m-%d %H:%M:%S'),
                 i['lastscan'].strftime('%Y-%m-%d %H:%M:%S')]
        else:
            _ = [i['ip'], i['port'], i['hostname'], i['vul_level'], i['info'],
                 i['vul_name'], i['title'], i['time'].strftime('%Y-%m-%d %H:%M:%S'), '']
        item.append(_)
    file = write_data(item, id)
    return file.getvalue()
