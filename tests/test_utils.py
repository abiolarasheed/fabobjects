# !*-* coding:utf-8 *-*
from __future__ import unicode_literals

import unittest

from fabric.api import env
from fabric.operations import local

from fabobjects.utils import (log_call, random_password,
                              return_distinct_servers,
                              server_host_manager, timing)
from tests.mock_objects import mock_stdout


class UtilsTestCase(unittest.TestCase):
    def test_random_password(self):
        self.assertEqual(len(random_password()), 12)
        self.assertEqual(len(random_password(bit=30)), 30)
        self.assertIsInstance(random_password(), str)

    def test_return_distinct_servers(self):
        class Server(object):
            def __init__(self, hostname):
                self.hostname = hostname
                self.cache = {'hostname': self.hostname}

        server1 = Server('test1.example.com')
        server2 = Server('test2.example.com')
        server3 = Server('test3.example.com')
        servers = [server1, server2, server3, server1, server2, server3]

        self.assertTrue(len(return_distinct_servers(servers)) == 3)

    def test_timing(self):

        @timing
        def fake_func():
            pass

        with mock_stdout() as fake_stdout:
            fake_func()
        self.assertTrue('fake_func function took ' in fake_stdout.getvalue())

    def test_log_call(self):
        @log_call
        def fake_func():
            pass

        with mock_stdout() as fake_stdout:
            fake_func()
        self.assertTrue(fake_func.__name__ in fake_stdout.getvalue())


class ServerHostManagerTestCase(unittest.TestCase):
    def test_local_call(self):
        env.key_filename = '~/.ssh/id_rsa.pub'

        class Server(object):
            def __init__(self):
                self.env = env
                self.user = "tester"
                self.ssh_port = 22
                self.ip = "127.0.0.1"
                self.get_password = "123456"
                self._host = "{0}@{1}:{2}".format(self.user,
                                                  self.ip,
                                                  self.ssh_port)

            @server_host_manager
            def test_uptime(self):
                local('uptime')
                return True

        self.assertTrue(Server().test_uptime())
