# coding=utf-8
import urllib2
import ssl
import base64

try:
    _create_unverified_https_context = ssl._create_unverified_context  # 忽略证书错误
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


def get_plugin_info():
    plugin_info = {
        "name": "锐捷AC弱口令",
        "info": "攻击者可进入web控制台，进而接管控制设备。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "banner:RGOS;port:80",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    error_i = 0
    user_list = ['admin']
    if port == 443:
        url = "https://" + ip + ":" + str(port) + "/login.do"
    else:
        url = "http://" + ip + ":" + str(port) + "/login.do"
    for user in user_list:
        for pass_ in PASSWORD_DIC:
            try:
                pass_ = str(pass_.replace('{user}', user))
                request = urllib2.Request(url)
                auth_str_temp = user + ':' + pass_
                auth_str = base64.b64encode(auth_str_temp)
                postdata = "auth=" + auth_str
                res = urllib2.urlopen(request, postdata, timeout=timeout)
                res_html = res.read()
                if "Success" in res_html:
                    return u'存在弱口令 %s:%s' % (user, pass_)
            except urllib2.HTTPError:
                break
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3: return
                continue
            else:
                pass
