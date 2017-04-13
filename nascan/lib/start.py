# coding:utf-8
import sys
import Queue
import threading
import scan
import icmp
import cidr

AC_PORT_LIST = {}
MASSCAN_AC = 0


class ThreadNum(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            try:
                task_host = self.queue.get(block=False)
            except:
                break
            try:
                if self.mode:
                    port_list = AC_PORT_LIST[task_host]
                else:
                    port_list = self.config_ini['Port_list'].split('|')[1].split('\n')
                _s = scan.scan(task_host, port_list)
                _s.config_ini = self.config_ini  # 提供配置信息
                _s.statistics = self.statistics  # 提供统计信息
                _s.run()
            except Exception, e:
                print e
            finally:
                self.queue.task_done()


class start:
    def __init__(self, config):  # 默认配置
        self.config_ini = config
        self.queue = Queue.Queue()
        self.thread = int(self.config_ini['Thread'])
        self.scan_list = self.config_ini['Scan_list'].split('\n')
        self.mode = int(self.config_ini['Masscan'].split('|')[0])
        self.icmp = int(self.config_ini['Port_list'].split('|')[0])

    def run(self):
        global AC_PORT_LIST
        all_ip_list = []
        for ip in self.scan_list:
            if "/" in ip: ip = cidr.CIDR(ip)
            if not ip:continue
            ip_list = self.get_ip_list(ip)
            if self.mode == 1:
                self.masscan_path = self.config_ini['Masscan'].split('|')[2]
                self.masscan_rate = self.config_ini['Masscan'].split('|')[1]
                ip_list = self.get_ac_ip(ip_list)
                self.masscan_ac[0] = 1
                AC_PORT_LIST = self.masscan(ip_list)  # 如果安装了Masscan即使用Masscan进行全端口扫描
                if not AC_PORT_LIST: continue
                self.masscan_ac[0] = 0
                for ip_str in AC_PORT_LIST.keys(): self.queue.put(ip_str)  # 加入队列
                self.scan_start()  # 开始扫描
            else:
                all_ip_list.extend(ip_list)
        if self.mode == 0:
            if self.icmp: all_ip_list = self.get_ac_ip(all_ip_list)
            for ip_str in all_ip_list: self.queue.put(ip_str)  # 加入队列
            self.scan_start()  # TCP探测模式开始扫描

    def scan_start(self):
        for i in range(self.thread):  # 开始扫描
            t = ThreadNum(self.queue)
            t.setDaemon(True)
            t.mode = self.mode
            t.config_ini = self.config_ini
            t.statistics = self.statistics
            t.start()
        self.queue.join()

    def masscan(self, ip):
        try:
            if len(ip) == 0: return
            sys.path.append(sys.path[0] + "/plugin")
            m_scan = __import__("masscan")
            result = m_scan.run(ip, self.masscan_path, self.masscan_rate)
            return result
        except Exception, e:
            print e
            print 'No masscan plugin detected'

    def get_ip_list(self, ip):
        ip_list_tmp = []
        iptonum = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
        numtoip = lambda x: '.'.join([str(x / (256 ** i) % 256) for i in range(3, -1, -1)])
        if '-' in ip:
            ip_range = ip.split('-')
            ip_start = long(iptonum(ip_range[0]))
            ip_end = long(iptonum(ip_range[1]))
            ip_count = ip_end - ip_start
            if ip_count >= 0 and ip_count <= 655360:
                for ip_num in range(ip_start, ip_end + 1):
                    ip_list_tmp.append(numtoip(ip_num))
            else:
                print 'IP format error'
        else:
            ip_split = ip.split('.')
            net = len(ip_split)
            if net == 2:
                for b in range(1, 255):
                    for c in range(1, 255):
                        ip = "%s.%s.%d.%d" % (ip_split[0], ip_split[1], b, c)
                        ip_list_tmp.append(ip)
            elif net == 3:
                for c in range(1, 255):
                    ip = "%s.%s.%s.%d" % (ip_split[0], ip_split[1], ip_split[2], c)
                    ip_list_tmp.append(ip)
            elif net == 4:
                ip_list_tmp.append(ip)
            else:
                print "IP format error"
        return ip_list_tmp

    def get_ac_ip(self, ip_list):
        try:
            s = icmp.Nscan()
            ipPool = set(ip_list)
            return s.mPing(ipPool)
        except Exception, e:
            print 'The current user permissions unable to send icmp packets'
            return ip_list
