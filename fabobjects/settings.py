# coding: utf-8
from __future__ import unicode_literals

from os.path import expanduser
from os.path import join
from fabric.api import env


HOME = expanduser("~")
env.user = ""
env.server_name = ""
env.colors = True
env.format = True

env.hosts = []
env.passwords = {}
env.key_filename = join(HOME, ".ssh/id_rsa.pub")
env_settings = env
