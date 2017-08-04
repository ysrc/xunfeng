#!/usr/bin/env python
# coding=utf-8
import urllib2
import re
import base64


def get_plugin_info():
    plugin_info = {
        "name": "Supervisor CVE-2017-11610",
        "info": "Supervisor 接口未授权访问、弱口令、代码执行漏洞",
        "level": "高危",
        "type": "弱口令",
        "author": "unknown",
        "url": "https://github.com/Medicean/VulApps/blob/master/s/supervisor/1/",
        "keyword": "port:9001",
        "source": 1
    }
    return plugin_info


def request(url, user="", password=""):
    data = """<?xml version="1.0"?>
    <methodCall>
    <methodName>supervisor.getSupervisorVersion</methodName>
    </methodCall>
    """
    req = urllib2.Request(url, data)
    if user != "" or password != "":
        basic = base64.b64encode("%s:%s" % (user, password))
        req.add_header(
            'Authorization', 'Basic %s' % basic)
    try:
        resp = urllib2.urlopen(req)
        if resp:
            respdata = resp.read()
            return respdata
    except:
        pass
    return None


def check_unauth(url):
    resp = request(url)
    if resp is not None and "<methodResponse>" in resp:
        return ("存在未授权访问漏洞", resp)
    return (None, resp)


def check(ip, port, timeout):
    user_list = ['user', 'admin', 'manager', 'root']
    url = "http://" + ip + ":" + str(port) + "/RPC2"
    retinfo = ""
    info, resp = check_unauth(url)
    if info is None:
        for user in user_list:
            for pass_ in PASSWORD_DIC:
                pass_ = str(pass_.replace('{user}', user))
                resp = request(url, user=user, password=pass_)
                if resp is None:
                    continue
                elif "<methodResponse>" in resp:
                    retinfo += "存在弱口令 %s:%s" % (user, pass_)
                    retinfo += ",并且%s" % checkversion(resp)
                    return retinfo
    else:
        retinfo = info
        retinfo += ",并且%s" % checkversion(resp)
    return retinfo


def checkversion(respdata):
    info = "存在远程代码执行漏洞 CVE-2017-11610"
    m = re.search('<string>(\d+?\.\d+?\.\d+?)</string>', respdata)
    if m:
        version = m.group(1)
    else:
        return ""
    if vc(version, "3.0.0") == '<':
        return ""
    if vc(version, "3.3.3") == "<" and vc(version, "3.3.0") != "<":
        return info
    if vc(version, "3.2.4") == "<" and vc(version, "3.2.0") != "<":
        return info
    if vc(version, "3.1.4") == "<" and vc(version, "3.1.0") != "<":
        return info
    if vc(version, "3.0.1") == "<" and vc(version, "3.0.0") != "<":
        return info


def vc(v1, v2):
    d1 = re.split('\.', v1)
    d2 = re.split('\.', v2)
    d1 = [int(d1[i]) for i in range(len(d1))]
    d2 = [int(d2[i]) for i in range(len(d2))]
    if(d1 > d2):
        return '>'
    if(d1 < d2):
        return '<'
    if(d1 == d2):
        return '='

if __name__ == '__main__':
    print check("127.0.0.1", 9001, 10)
