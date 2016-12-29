#!/usr/bin/env python
#-*- coding: utf-8 -*-
import socket

def get_plugin_info():
	plugin_info = {
		"name": "WebLogic 反序列化代码执行",
		"info": "漏洞的成因是WLS Security组件允许远程攻击者执行任意命令。攻击者通过向发送T3协议流量，其中包含精心构造的序列化Java对象利用此漏洞。",
		"level": "紧急",
		"type": "代码执行",
		"author": "Dee Ng<d33.n99@gmail.com>",
		"url": "https://blogs.oracle.com/security/entry/security_alert_cve_2015_4852",
		"keyword": "tag:webLogic",
		"source": 1
	}
	return plugin_info

def check(ip, port, timeout):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))
		s.sendall('t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n')
		version = s.recv(64)
		if(version == 'HELO'): version += s.recv(64)
		s.close()
		for af_version in ('10.3.6.0', '12.1.2.0', '12.1.3.0', '12.2.1.0'):
			if(af_version in version):return u"可能存在WebLogic 反序列化代码执行漏洞"
	except:
		return
