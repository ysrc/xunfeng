# coding=utf-8
import urllib2
import re

def get_plugin_info():
    plugin_info = {
        "name": "phpMyAdmin弱口令",
        "info": "导致数据库敏感信息泄露，严重可导致服务器被入侵控制。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:phpmyadmin",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    flag_list = ['src="navigation.php', 'frameborder="0" id="frame_content"', 'id="li_server_type">',
                 'class="disableAjax" title=']
    user_list = ['root', 'mysql', 'www', 'bbs', 'wwwroot', 'bak', 'backup']
    error_i = 0
    try:
        res_html = urllib2.urlopen('http://' + ip + ":" + str(port), timeout=timeout).read()
        if 'input_password' in res_html and 'name="token"' in res_html:
            url = 'http://' + ip + ":" + str(port) + "/index.php"
        else:
            res_html = urllib2.urlopen('http://' + ip + ":" + str(port) + "/phpmyadmin", timeout=timeout).read()
            if 'input_password' in res_html and 'name="token"' in res_html:
                url = 'http://' + ip + ":" + str(port) + "/phpmyadmin/index.php"
            else:
                return
    except:
        pass
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
                res_html = opener.open(url, timeout=timeout).read()
                token = re.search('name="token" value="(.*?)" />', res_html)
                token_hash = urllib2.quote(token.group(1))
                postdata = "pma_username=%s&pma_password=%s&server=1&target=index.php&lang=zh_CN&collation_connection=utf8_general_ci&token=%s" % (
                user, password, token_hash)
                res = opener.open(url,postdata, timeout=timeout)
                res_html = res.read()
                for flag in flag_list:
                    if flag in res_html:
                        return u'phpmyadmin弱口令，账号：%s 密码：%s' % (user, password)
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3: return
            except Exception,e:
                return