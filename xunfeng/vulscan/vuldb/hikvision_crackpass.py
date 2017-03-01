# coding:utf-8
import urllib2
import base64


def get_plugin_info():
    plugin_info = {
        "name": "海康威视摄像头弱口令",
        "info": "攻击者可进入web控制台，进而接管控制设备。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:hikvision",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    error_i = 0
    flag_list = ['>true</']
    user_list = ['admin']
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = 'http://' + ip + ":" + str(port) + '/ISAPI/Security/userCheck'
                request = urllib2.Request(login_url)
                auth_str_temp = user + ':' + password
                auth_str = base64.b64encode(auth_str_temp)
                request.add_header('Authorization', 'Basic ' + auth_str)
                res = urllib2.urlopen(request, timeout=timeout)
                res_code = res.code
                res_html = res.read()
            except urllib2.HTTPError, e:
                res_code = e.code
                res_html = e.read()
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3: return
                continue
            if int(res_code) == 404 or int(res_code) == 403: return
            if int(res_code) == 401: continue
            for flag in flag_list:
                if flag in res_html:
                    return u'Hikvision网络摄像头弱口令 %s:%s' % (user, password)
