#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime

from mongoengine import *


class Report(Document):
	meta = {
		'collection': 'report'
	}
	assetId = ObjectIdField()
	assetName = StringField(max_length=200, required=True, unique=True)
	password = StringField(max_length=200, required=True)
	createTime = DateTimeField(default=datetime.datetime.now)
	updateTime = DateTimeField(default=datetime.datetime.now)
	lastLoginTime = DateTimeField(default=datetime.datetime.now)
	enable = BooleanField(default=True)
	loginErrorTimes = IntField(default=0)
	description = StringField(max_length=200)
