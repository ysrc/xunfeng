# coding=utf-8
import socket
import time


def get_plugin_info():
    plugin_info = {
        "name": "IIS WebDav RCE",
        "info": "CVE-2017-7269,Windows Server 2003R2版本IIS6.0的WebDAV服务中的ScStoragePathFromUrl函数存在缓存区溢出漏洞，远程攻击者通过以“If: <http://”开头的长header PROPFIND请求，执行任意代码，进而导致服务器被入侵控制。",
        "level": "紧急",
        "type": "远程溢出",
        "author": "wolf@YSRC",
        "url": "http://www.freebuf.com/vuls/130531.html",
        "keyword": "tag:iis",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        pay = "OPTIONS / HTTP/1.0\r\n\r\n"
        s.send(pay) 
        data = s.recv(2048)
        s.close()
        if "PROPFIND" in data and "Microsoft-IIS/6.0" in data :
            return u"可能存在IIS WebDav 远程代码执行漏洞"
    except:
        pass
