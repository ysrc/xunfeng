#!/usr/bin/env python
# coding: utf-8


import multiprocessing

from xunfeng.aider.Aider import main as main_aider
from xunfeng.nascan.NAScan import main as main_nascan
from xunfeng.vulscan.VulScan import main as main_vulscan


# Windows 平台要加上这句，避免 RuntimeError
multiprocessing.freeze_support()
pool = multiprocessing.Pool()


def main():
    pool.apply_async(main_aider, args=())
    pool.apply_async(main_nascan, args=())
    pool.apply_async(main_vulscan, args=())

    pool.close()
    pool.join()


if __name__ == '__main__':
    main()
