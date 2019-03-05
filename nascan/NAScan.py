# coding:utf-8
# author:wolf@YSRC
import thread
from lib.common import *
from lib.start import *
if __name__ == "__main__":
    try:
        CONFIG_INI = get_config()  # 读取配置
        log.write('info', None, 0, u'获取配置成功')
        STATISTICS = get_statistics()  # 读取统计信息
        MASSCAN_AC = [0]
        NACHANGE = [0]
        thread.start_new_thread(
            monitor, (CONFIG_INI, STATISTICS, NACHANGE))  # 心跳线程
        thread.start_new_thread(cruise, (STATISTICS, MASSCAN_AC))  # 失效记录删除线程
        socket.setdefaulttimeout(int(CONFIG_INI['Timeout']) / 2)  # 设置连接超时
        ac_data = []
        while True:
            now_time = time.localtime()
            now_hour = now_time.tm_hour
            now_day = now_time.tm_mday
            now_date = str(now_time.tm_year) + \
                str(now_time.tm_mon) + str(now_day)
            cy_day, ac_hour = CONFIG_INI['Cycle'].split('|')
            log.write('info', None, 0, u'扫描规则: ' + str(CONFIG_INI['Cycle']))
            # 判断是否进入扫描时段
            if (now_hour == int(ac_hour) and now_day % int(cy_day) == 0 and now_date not in ac_data) or NACHANGE[0]:
                ac_data.append(now_date)
                NACHANGE[0] = 0
                log.write('info', None, 0, u'开始扫描')
                s = start(CONFIG_INI)
                s.masscan_ac = MASSCAN_AC
                s.statistics = STATISTICS
                s.run()
            time.sleep(60)
    except Exception, e:
        print e
