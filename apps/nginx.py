# coding: utf-8
from __future__ import unicode_literals


from apps.base import BaseApp


class NginxServer(BaseApp):
    def __init__(self, *args, **kwargs):
        super(NginxServer, self).__init__(*args, **kwargs)
        self.service_name = "nginx"
        self.service_port = kwargs.get("service_port", "80")
