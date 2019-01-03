# coding: utf-8
from __future__ import unicode_literals

from apps.base import BaseApp


class DjangoApp(BaseApp):
    def __init__(self, *args, **kwargs):
        super(DjangoApp, self).__init__(*args, **kwargs)
        self.app_user = kwargs.get("app_user") or self.env.app_user
        self.supervised = kwargs["supervised"]
