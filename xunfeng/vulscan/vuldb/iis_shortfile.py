# coding:utf-8
import urllib2


def get_plugin_info():
    plugin_info = {
        "name": "IIS短文件名",
        "info": "攻击者可利用此特性猜解出目录与文件名，以达到类似列目录漏洞的效果。",
        "level": "低危",
        "type": "信息泄露",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:iis",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        url = ip + ":" + str(port)
        flag_400 = '/otua*~1.*/.aspx'
        flag_404 = '/*~1.*/.aspx'
        request = urllib2.Request('http://' + url + flag_400)
        req = urllib2.urlopen(request, timeout=timeout)
        if int(req.code) == 400:
            req_404 = urllib2.urlopen('http://' + url + flag_404, timeout=timeout)
            if int(req_404.code) == 404:
                return u'iis 短文件名猜解漏洞'
    except Exception, e:
        pass
