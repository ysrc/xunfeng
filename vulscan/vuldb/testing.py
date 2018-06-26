#!/usr/bin/env python
# coding=utf-8
""" File: vulscan/vuldb/testing.py """

import imp
import sys
import os
import random
from string import digits, ascii_lowercase

PASSWORD_DIC = []  # set password list for plugin

def get_base_path():
    return os.path.dirname(os.path.realpath(__file__))


def get_random_string(length=32, case_pool=digits+ascii_lowercase):
    return ''.join([random.choice(case_pool) for _ in range(length)])


def import_file(path):
    return imp.load_source(get_random_string(), path)


def main():
    filter_word = ''
    default_timeout = 10
    try:
        filter_word = sys.argv[1]
        ip_addr = sys.argv[2]
        port = sys.argv[3]
    except IndexError:
        print('[!] usage: python testing.py file_filter ip port')
        print('[!] usage: python testing.py phpmyadmin 127.0.0.1 8080')
        exit(1)

    print('[*] current filter_word is: %s' %filter_word)
    base_path = get_base_path()
    for filename in os.listdir(os.path.realpath(base_path)):
        if not (filename.endswith('.py') and filter_word in filename):
            continue
        filepath = os.path.join(base_path, filename)
        _module = import_file(filepath)
        setattr(_module, 'PASSWORD_DIC', PASSWORD_DIC)
        res = _module.check(ip_addr, int(port), default_timeout)
        if not res:
            res = 'not exist'
        name = _module.get_plugin_info().get('name')
        print(name)
        print(res)


if __name__ == '__main__':
    main()
