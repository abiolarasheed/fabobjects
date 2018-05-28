# coding: utf-8
from __future__ import unicode_literals

from apps.base import BaseApp


class RedisServer(BaseApp):
    def __init__(self, *args, **kwargs):
        super(RedisServer,self).__init__(*args,**kwargs)
        self.service_name = 'redis-server'
        self.service_port = kwargs.get('service_port', '6379')
