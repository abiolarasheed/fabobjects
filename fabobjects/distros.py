# coding: utf-8
from __future__ import with_statement


class BaseServer(object):
    """
    An SSH daemon connection.
    **Basics**
    This class performs useful high level operations over ssh.
    """
    def __init__(self, *args, **kwargs):
        pass

    def sudo(self, *args, **kwargs):
        raise NotImplementedError

    def run(self, *args, **kwargs):
        raise NotImplementedError
