#!/usr/bin/env python
# coding: utf-8

from View import app

if __name__ == '__main__':
    app.debug = True
    app.run(threaded=True, port=8080, host='0.0.0.0')
