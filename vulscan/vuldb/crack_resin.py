# coding=utf-8
# author:wolf
import urllib2


def get_plugin_info():
    plugin_info = {
        "name": "Resin控制台弱口令",
        "info": "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "http://www.360doc.com/content/15/0722/22/11644963_486744404.shtml",
        "keyword": "tag:resin",
        "source": 1
    }
    return plugin_info


def check(host, port, timeout):
    url = "http://%s:%d" % (host, int(port))
    error_i = 0
    flag_list = ['<th>Resin home:</th>', 'The Resin version', 'Resin Summary']
    user_list = ['admin']
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                PostStr = 'j_username=%s&j_password=%s' % (user, password)
                res = opener.open(url + '/resin-admin/j_security_check?j_uri=index.php', PostStr ,timeout=timeout)
                res_html = res.read()
                res_code = res.code
            except urllib2.HTTPError, e:
                return
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3:
                    return
                continue
            for flag in flag_list:
                if flag in res_html or int(res_code) == 408:
                    info = u'%s/resin-admin 存在弱口令 用户名：%s，密码：%s' % (url, user, password)
                    return info
