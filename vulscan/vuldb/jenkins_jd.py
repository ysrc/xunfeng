#!/usr/bin/env python
#-*- coding: utf-8 -*-
import urllib2, ssl
import socket

def get_plugin_info():
	plugin_info = {
		"name": "Jenkins反序列化代码执行",
		"info": "漏洞的成因是Apache Commons Collections (ACC) 3.2.1及4.0版本未能正确验证用户输入，其InvokerTransformer类在反序列化来自可疑域的数据时存在安全漏洞，这可使攻击者在用户输入中附加恶意代码并组合运用不同类的readObject()方法，在最终类型检查之前执行Java函数或字节码（包括调用Runtime.exec()执行本地OS命令）。",
		"level": "紧急",
		"type": "代码执行",
		"author": "Dee Ng<d33.n99@gmail.com>",
		"url": "",
		"keyword": "tag:jenkins",
		"source": 1
	}
	return plugin_info

def check(ip, port, timeout):
	try:
		j_version = False
		cli_port = False
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		output = urllib2.urlopen('https://'+ip+":"+str(port)+"/jenkins/", context=ctx, timeout=10).info()
		cli_port =  int(output['X-Jenkins-CLI-Port'])
		j_version = float(output['X-Jenkins'])
	except urllib2.HTTPError, e:
		if (e.getcode() == 404):
			try:
				output = urllib2.urlopen('https://'+ip+":"+str(port), context=ctx, timeout=10).info()
				cli_port =  int(output['X-Jenkins-CLI-Port'])
				j_version = float(output['X-Jenkins'])
			except:pass
	except:pass

	if(cli_port == False):
		try:
			output = urllib2.urlopen('http://'+ip+":"+str(port)+"/jenkins/", context=ctx, timeout=10).read()
			cli_port =  int(output['X-Jenkins-CLI-Port'])
			j_version = float(output['X-Jenkins'])
		except urllib2.HTTPError, e:
			if (e.getcode() == 404):
				try:
					output = urllib2.urlopen('http://'+ip+":"+str(port), context=ctx, timeout=10).info()
					cli_port =  int(output['X-Jenkins-CLI-Port'])
					j_version = float(output['X-Jenkins'])
				except:pass
		except:return

	if(j_version >= 1.638):return

	try:
		server_address = (ip, cli_port)
		sock = socket.create_connection(server_address, 5)
		sock.settimeout(10)
		sock.send('\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74')
		data1 = sock.recv(1024)
		if "rO0AB" in data1:return u"可能存在Jenkins反序列化代码执行漏洞"
		data2 = sock.recv(1024)
		if "rO0AB" in data2:return u"可能存在Jenkins反序列化代码执行漏洞"
	except:return
