def stringxor(str1, str2):
    orxstr = ""
    for i in range(0, len(str1)):
        rst = int(str1[i]) & int(str2[i])
        orxstr = orxstr + str(rst)
    return orxstr


def bin2dec(string_num):
    return str(int(string_num, 2))


def getip(ip, type):
    result = ''
    for i in range(4):
        item = bin2dec(ip[0:8])
        if i == 3:
            if type == 0:
                item = str(int(item) + 1)
            else:
                item = str(int(item) - 1)
        result = result + item + '.'
        ip = ip[8:]
    return result.strip('.')


def CIDR(input):
    try:
        ip = input.split('/')[0]
        pos = int(input.split('/')[1])
        ipstr = ''
        for i in ip.split('.'):
            ipstr = ipstr + bin(int(i)).replace('0b', '').zfill(8)
        pstr = '1' * pos + '0' * (32 - pos)
        res = stringxor(ipstr, pstr)
        _ip = getip(res, 0), getip(res[0:pos] + '1' * (32 - pos), 1)
        return _ip[0] + "-" + _ip[1]
    except:
        return
