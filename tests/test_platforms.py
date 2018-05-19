# coding: utf-8
from __future__ import unicode_literals

import unittest

from fabobjects.platforms import (auto_detect_os,
                                  is_debian, is_redhat)


class DetectOsTestCase(unittest.TestCase):
    def test_is_debian(self):
        self.assertTrue(is_debian('ubuntu'))

    def test_is_redhat(self):
        self.assertTrue(is_redhat('centos'))

    def test_auto_detect_debian(self):
        self.assertTrue(auto_detect_os("ubuntu") == 'Debian')

    def test_auto_detect_redhat(self):
        self.assertTrue(auto_detect_os("centos") == 'Redhat')

    def test_auto_detect_unknown_os(self):
        self.assertTrue(auto_detect_os("windows") == 'Unknown')
