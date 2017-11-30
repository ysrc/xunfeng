# -*- coding: UTF-8 -*-

from functools import wraps
from flask import url_for, redirect, request


# 检查referer
def anticsrf(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            if request.referrer and request.referrer.replace('http://', '').split('/')[0] == request.host:
                return f(*args, **kwargs)
            else:
                return redirect('/400')
        except Exception, e:
            print e
            return redirect('/500')

    return wrapper
