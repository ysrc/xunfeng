import socket,thread,datetime,time
query_history = []
url_history = []
def web_server():
    web = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    web.bind(('0.0.0.0',8088))
    web.listen(10)
    while True:
        try:
            conn,addr = web.accept()
            data = conn.recv(4096)
            req_line = data.split("\r\n")[0]
            path = req_line.split()[1]
            route_list = path.split('/')
            html = "NO"
            if len(route_list) == 3:
                if route_list[1] == 'add':
                    if route_list[2] not in url_history:
                        url_history.append(route_list[2])
                elif route_list[1] == 'check':
                    if route_list[2] in url_history:
                        url_history.remove(route_list[2])
                        html = 'YES'
            else:
                query_str = route_list[1]
                for query_raw in query_history:
                    if query_str in query_raw:
                        query_history.remove(query_raw)
                        html = "YES"
            print datetime.datetime.now().strftime('%m-%d %H:%M:%S') + " " + str(addr[0]) +' web query: ' + path
            raw = "HTTP/1.0 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" %(len(html),html)
            conn.send(raw)
            conn.close()
        except:
            pass
if __name__=="__main__":
    dns = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    dns.bind(('0.0.0.0',53))
    thread.start_new_thread(web_server,())
    while True:
        try:
            time.sleep(1)
            recv,addr = dns.recvfrom(1024)
            if recv not in query_history:query_history.append(recv)
            print datetime.datetime.now().strftime('%m-%d %H:%M:%S') + " " +str(addr[0]) +' Dns Query: ' + recv
        except Exception,e:
            print e
            continue
