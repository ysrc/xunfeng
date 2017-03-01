#!/usr/bin/env python
# coding=utf-8

from setuptools import find_packages, setup

from xunfeng import VERSION

setup(
    name='xunfeng',
    version=VERSION,
    url='https://github.com/ysrc/xunfeng',
    description='巡风是一款适用于企业内网的漏洞快速应急，巡航扫描系统。',
    author='ysrc',
    author_email='',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "xunfeng = xunfeng.cli:main"
        ]
    },
    install_requires=[
        'six>=1.6.0',
        'Flask',
        'pymongo',
        'xlwt',
        'paramiko',
        'packaging',
        'appdirs',
        'pytest'  # 单元测试依赖库
    ],
    extras_require={}
)
