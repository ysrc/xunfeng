#coding:utf-8
#author:wolf
import os
def run(ip_list,path,rate):
    try:
        ip_file = open('target.log','w')
        ip_file.write("\n".join(ip_list))
        ip_file.close()
        path = str(path).translate(None, ';|&')
        rate = str(rate).translate(None, ';|&')
        if not os.path.exists(path):return
        os.system("%s -p1-65535 -iL target.log -oL tmp.log --randomize-hosts --rate=%s"%(path,rate))
        result_file = open('tmp.log', 'r')
        result_json = result_file.readlines()
        result_file.close()
        del result_json[0]
        del result_json[-1]
        open_list = {}
        for res in result_json:
            try:
                ip = res.split()[3]
                port = res.split()[2]
                if ip in open_list:
                    open_list[ip].append(port)
                else:
                    open_list[ip] = [port]
            except:pass
        os.remove('target.log')
        os.remove('tmp.log')
        return open_list
    except:
        pass
