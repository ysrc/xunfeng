# coding:utf-8
import socket


def get_plugin_info():
    plugin_info = {
        "name": "Memcache未授权访问",
        "info": "导致数据库敏感信息泄露。",
        "level": "中危",
        "type": "未授权访问",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "server:memcache",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("stats\r\n")
        result = s.recv(1024)
        if "STAT version" in result:
            return u"未授权访问"
    except Exception, e:
        pass
