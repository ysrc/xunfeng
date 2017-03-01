# coding=utf-8
import socket
import time
import urllib2


def get_plugin_info():
    plugin_info = {
        "name": "IIS WebDav",
        "info": "开启了WebDav且配置不当可导致攻击者直接上传webshell，进而导致服务器被入侵控制。",
        "level": "紧急",
        "type": "任意文件上传",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:iis",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        flag = "PUT /vultest.txt HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 9\r\n\r\nxxscan0\r\n\r\n" % (ip, port)
        s.send(flag)
        time.sleep(1)
        data = s.recv(1024)
        s.close()
        if 'PUT' in data:
            url = 'http://' + ip + ":" + str(port) + '/vultest.txt'
            request = urllib2.Request(url)
            res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
            if 'xxscan0' in res_html:
                return u"iis webdav漏洞"
    except Exception, e:
        pass
