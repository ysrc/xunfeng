# coding:utf-8
import mongo
import log
import socket
import datetime
import urllib2
import re
import time
import ssl
import gzip
import StringIO

try:
    _create_unverified_https_context = ssl._create_unverified_context  # 忽略证书错误
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


class scan:
    def __init__(self, task_host, port_list):
        self.ip = task_host
        self.port_list = port_list
        self.config_ini = {}

    def run(self):
        self.timeout = int(self.config_ini['Timeout'])
        for _port in self.port_list:
            self.server = ''
            self.banner = ''
            self.port = int(_port)
            self.scan_port()  # 端口扫描
            if not self.banner:
                continue
            self.server_discern()  # 服务识别
            if self.server == '':
                web_info = self.try_web()  # 尝试web访问
                if web_info:
                    log.write('web', self.ip, self.port, web_info)
                    time_ = datetime.datetime.now()
                    mongo.NA_INFO.update({'ip': self.ip, 'port': self.port},
                                         {"$set": {'banner': self.banner, 'server': 'web', 'webinfo': web_info,
                                                   'time': time_}})

    def scan_port(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((self.ip, self.port))
            time.sleep(0.2)
        except Exception, e:
            return
        try:
            self.banner = sock.recv(1024)
            sock.close()
            if len(self.banner) <= 2:
                self.banner = 'NULL'
        except Exception, e:
            self.banner = 'NULL'
        log.write('portscan', self.ip, self.port, None)
        banner = ''
        hostname = self.ip2hostname(self.ip)
        time_ = datetime.datetime.now()
        date_ = time_.strftime('%Y-%m-%d')
        try:
            banner = unicode(self.banner, errors='replace')
            if self.banner == 'NULL':
                banner = ''
            mongo.NA_INFO.insert({"ip": self.ip, "port": self.port,
                                  "hostname": hostname, "banner": banner, "time": time_})
            self.statistics[date_]['add'] += 1
        except:
            if banner:
                history_info = mongo.NA_INFO.find_and_modify(
                    query={"ip": self.ip, "port": self.port, "banner": {"$ne": banner}}, remove=True)
                if history_info:
                    mongo.NA_INFO.insert(
                        {"ip": self.ip, "port": self.port, "hostname": hostname, "banner": banner, "time": time_})
                    self.statistics[date_]['update'] += 1
                    del history_info["_id"]
                    history_info['del_time'] = time_
                    history_info['type'] = 'update'
                    mongo.NA_HISTORY.insert(history_info)

    def server_discern(self):
        for mark_info in self.config_ini['Discern_server']:  # 快速识别
            try:
                name, default_port, mode, reg = mark_info
                if mode == 'default':
                    if int(default_port) == self.port:
                        self.server = name
                elif mode == 'banner':
                    matchObj = re.search(reg, self.banner, re.I | re.M)
                    if matchObj:
                        self.server = name
                if self.server:
                    break
            except:
                continue
        if not self.server and self.port not in [80, 443, 8080]:
            for mark_info in self.config_ini['Discern_server']:  # 发包识别
                try:
                    name, default_port, mode, reg = mark_info
                    if mode not in ['default', 'banner']:
                        dis_sock = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)
                        dis_sock.connect((self.ip, self.port))
                        mode = mode.decode('string_escape')
                        reg = reg.decode('string_escape')
                        dis_sock.send(mode)
                        time.sleep(0.3)
                        dis_recv = dis_sock.recv(1024)
                        dis_sock.close()
                        matchObj = re.search(reg, dis_recv, re.I | re.M)
                        if matchObj:
                            self.server = name
                            break
                except:
                    pass
        if self.server:
            log.write("server", self.ip, self.port, self.server)
            mongo.NA_INFO.update({"ip": self.ip, "port": self.port}, {
                                 "$set": {"server": self.server}})

    def try_web(self):
        title_str, html = '', ''
        try:
            if self.port == 443:
                info = urllib2.urlopen("https://%s:%s" %
                                       (self.ip, self.port), timeout=self.timeout)
            else:
                info = urllib2.urlopen("http://%s:%s" %
                                       (self.ip, self.port), timeout=self.timeout)
            html = info.read()
            header = info.headers
        except urllib2.HTTPError, e:
            html = e.read()
            header = e.headers
        except:
            return
        if not header:
            return
        # 解压gzip
        if 'Content-Encoding' in header and 'gzip' in header['Content-Encoding']:
            html_data = StringIO.StringIO(html)
            gz = gzip.GzipFile(fileobj=html_data)
            html = gz.read()
        try:
            html_code = self.get_code(header, html).strip()
            if html_code and len(html_code) < 12:
                html = html.decode(html_code).encode('utf-8')
        except:
            pass
        try:
            title = re.search(r'<title>(.*?)</title>', html, flags=re.I | re.M)
            if title:
                title_str = title.group(1)
        except:
            pass
        try:
            web_banner = str(header) + "\r\n\r\n" + html
            self.banner = web_banner
            history_info = mongo.NA_INFO.find_one(
                {"ip": self.ip, "port": self.port})
            if 'server' not in history_info:
                tag = self.get_tag()
                web_info = {'title': title_str, 'tag': tag}
                return web_info
            else:
                if abs(len(history_info['banner'].encode('utf-8')) - len(web_banner)) > len(web_banner) / 60:
                    del history_info['_id']
                    history_info['del_time'] = datetime.datetime.now()
                    mongo.NA_HISTORY.insert(history_info)
                    tag = self.get_tag()
                    web_info = {'title': title_str, 'tag': tag}
                    date_ = datetime.datetime.now().strftime('%Y-%m-%d')
                    self.statistics[date_]['update'] += 1
                    log.write('info', None, 0, '%s:%s update web info' %
                              (self.ip, self.port))
                    return web_info
        except:
            return

    def ip2hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            pass
        try:
            query_data = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41" + \
                         "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41" + \
                         "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
            dport = 137
            _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _s.settimeout(3)
            _s.sendto(query_data, (ip, dport))
            x = _s.recvfrom(1024)
            tmp = x[0][57:]
            _s.close()
            hostname = tmp.split("\x00", 2)[0].strip()
            hostname = hostname.split()[0]
            return hostname
        except:
            pass

    def get_code(self, header, html):
        try:
            m = re.search(r'<meta.*?charset=(.*?)"(>| |/)', html, flags=re.I)
            if m:
                return m.group(1).replace('"', '')
        except:
            pass
        try:
            if 'Content-Type' in header:
                Content_Type = header['Content-Type']
                m = re.search(r'.*?charset=(.*?)(;|$)',
                              Content_Type, flags=re.I)
                if m:
                    return m.group(1)
        except:
            pass

    def get_tag(self):
        try:
            url = self.ip + ':' + str(self.port)
            tag = map(self.discern, [
                      'Discern_cms', 'Discern_con', 'Discern_lang'], [url, url, url])
            return filter(None, tag)
        except Exception, e:
            return

    def discern(self, dis_type, domain):
        file_tmp = {}
        if int(domain.split(":")[1]) == 443:
            protocol = "https://"
        else:
            protocol = "http://"
        try:
            req = urllib2.urlopen(protocol + domain, timeout=self.timeout)
            header = req.headers
            html = req.read()
        except urllib2.HTTPError, e:
            html = e.read()
            header = e.headers
        except Exception, e:
            return
        for mark_info in self.config_ini[dis_type]:
            if mark_info[1] == 'header':
                try:
                    if not header:
                        return
                    if re.search(mark_info[3], header[mark_info[2]], re.I):
                        return mark_info[0]
                except Exception, e:
                    continue
            elif mark_info[1] == 'file':
                if mark_info[2] == 'index':
                    try:
                        if not html:
                            return
                        if re.search(mark_info[3], html, re.I):
                            return mark_info[0]
                    except Exception, e:
                        continue
                else:
                    if mark_info[2] in file_tmp:
                        re_html = file_tmp[mark_info[2]]
                    else:
                        try:
                            re_html = urllib2.urlopen(protocol + domain + "/" + mark_info[2],
                                                      timeout=self.timeout).read()
                        except urllib2.HTTPError, e:
                            re_html = e.read()
                        except Exception, e:
                            return
                        file_tmp[mark_info[2]] = re_html
                    try:
                        if re.search(mark_info[3], re_html, re.I):
                            return mark_info[0]
                    except Exception, e:
                        print mark_info[3]
