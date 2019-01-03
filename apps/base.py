# coding: utf-8
from __future__ import unicode_literals


class BaseApp(object):
    """
    A base application that implements minimal functions most apps should have.
    """

    def __init__(self, *args, **kwargs):
        pass

    def delopy(self):
        """
        A method to install the application on the host server.
        :return: string
        """
        raise NotImplementedError

    def start(self):
        """
        A method for starting the application.
        :return: string
        """
        raise NotImplementedError

    def stop(self):
        """
        A method for stopping the application.
        :return: string
        """
        raise NotImplementedError

    def restart(self):
        """
        A method for restarting the application.
        :return: string
        """
        raise NotImplementedError

    def reload(self):
        """
        A method for reload the application.
        :return:
        """
        raise NotImplementedError

    def expose(self, port=None, interface=None, from_ip=None, proto="tcp", **kwargs):
        """
        A method for exposing the application over the internet, this is mostly firewall.
        :param port: int
        :param interface: string
        :param from_ip: sting
        :param kwargs: dict
        :return:
        """
        raise NotImplementedError

    def connect(self, app):
        raise NotImplementedError

    def configure(self, *args, **kwargs):
        raise NotImplementedError
