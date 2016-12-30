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
                return redirect(url_for('NotFound'))
        except Exception, e:
            print e
            return redirect(url_for('Error'))

    return wrapper
