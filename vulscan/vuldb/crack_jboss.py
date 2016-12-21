# coding=utf-8
# author:wolf
import base64
import re
import urllib2

def get_plugin_info():
    plugin_info = {
        "name": "Jboss弱口令",
        "info": "攻击者通过此漏洞可以登陆管理控制台，通过部署功能可直接获取服务器权限。",
        "level": "高危",
        "type": "弱口令",
        "author": "wolf@YSRC",
        "url": "http://www.shack2.org/article/156.html",
        "keyword": "tag:jboss",
        "source": 1
    }
    return plugin_info

def check(host,port,timeout):
    url = "http://%s:%d"%(host,int(port))
    error_i = 0
    flag_list=['>jboss.j2ee</a>','JBoss JMX Management Console','HtmlAdaptor?action=displayMBeans','<title>JBoss Management']
    user_list=['admin','manager','jboss','root']
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = url+'/jmx-console'
                request = urllib2.Request(login_url)
                auth_str_temp=user+':'+password
                auth_str=base64.b64encode(auth_str_temp)
                request.add_header('Authorization', 'Basic '+auth_str)
                res = urllib2.urlopen(request,timeout=timeout)
                res_code = res.code
                res_html = res.read()
            except urllib2.HTTPError,e:
                res_code = e.code
                res_html = e.read()
            except urllib2.URLError,e:
                error_i+=1
                if error_i >= 3:
                    return
                continue
            if int(res_code) == 404:
                break
            if int(res_code) == 401:
                continue
            for flag in flag_list:
                if flag in res_html:
                    info = u'存在弱口令，用户名：%s，密码：%s'%(user,password)
                    return info
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = url+'/console/App.html'
                request = urllib2.Request(login_url)
                auth_str_temp=user+':'+password
                auth_str=base64.b64encode(auth_str_temp)
                request.add_header('Authorization', 'Basic '+auth_str)
                res = urllib2.urlopen(request,timeout=timeout)
                res_code = res.code
                res_html = res.read()
            except urllib2.HTTPError,e:
                res_code = e.code
            except urllib2.URLError,e:
                error_i+=1
                if error_i >= 3:
                    return
                continue
            if int(res_code) == 404:
                break
            if int(res_code) == 401:
                continue
            for flag in flag_list:
                if flag in res_html:
                    info = u'存在弱口令，用户名：%s，密码：%s' % (user, password)
                    return info
    for user in user_list:
        for password in PASSWORD_DIC:
            try:
                login_url = url+'/admin-console/login.seam'
                res_html = urllib2.urlopen(login_url).read()
                if '"http://jboss.org/embjopr/"' in res_html:
                    key_str=re.search('javax.faces.ViewState\" value=\"(.*?)\"',res_html)
                    key_hash=urllib.quote(key_str.group(1))
                    PostStr="login_form=login_form&login_form:name=%s&login_form:password=%s&login_form:submit=Login&javax.faces.ViewState=%s"%(user,password,key_hash)
                    request = urllib2.Request(login_url,PostStr)
                    res = urllib2.urlopen(request,timeout=timeout)
                    if 'admin-console/secure/summary.seam' in res.read():
                        info = u'存在弱口令，用户名：%s，密码：%s' % (user, password)
                        return info
            except:
                pass
