# coding: utf-8
from __future__ import with_statement

import os

from fabric.context_managers import settings

from fabobjects.utils import server_host_manager


class BaseServer(object):
    """
    An SSH daemon connection.
    **Basics**
    This class performs useful high level operations over ssh.
    """
    def __init__(self, *args, **kwargs):
        pass

    def clear_screen(self):
        os.system('clear')

    def sudo(self, *args, **kwargs):
        raise NotImplementedError

    def run(self, *args, **kwargs):
        raise NotImplementedError


class BSD(BaseServer):
    def __init__(self, *args, **kwargs):
        super(BSD, self).__init__(*args, **kwargs)

    @property
    def distro(self):
        return 'BSD'

    def _pkg(self):
        pass

    @server_host_manager
    def uninstall(self, package):
        pass

    @server_host_manager
    def is_package_installed(self, package_name):
        pass

    def get_package_manager(self):
        return self._pkg()

    @server_host_manager
    def list_compilers(self):
        pass

    @server_host_manager
    def list_installed_packages(self):
        pass


class Debian(BaseServer):
    def __init__(self, *args, **kwargs):
        super(Debian, self).__init__(*args, **kwargs)

    def _apt(self):
        return "apt-get "

    @property
    def distro(self):
        return 'Debian'

    @server_host_manager
    def uninstall(self, package):
        uninstall = '{0} --purge remove {1} -y'.\
            format(self.get_package_manager(), package)
        with settings(warn_only=True):
            self.sudo(uninstall)
            self.sudo('apt-get autoremove')

    @server_host_manager
    def is_package_installed(self, package_name):
        """
        Returns True if a given package is install on os
        """
        with settings(warn_only=True):
            info = self.sudo('dpkg -s %s'.format(package_name))
            if info.split('\n')[1] == 'Status: install ok installed\r':
                return True
            return False

    def get_package_manager(self):
        return self._apt()

    @server_host_manager
    def list_compilers(self):
        result = self.sudo("dpkg --list | grep gcc")
        return result

    @server_host_manager
    def list_installed_packages(self):
        result = self.sudo("dpkg --list")
        return result


class RedHat(BaseServer):
    def _yum(self):
        return "yum "

    def get_package_manager(self):
        return self._yum()

    @server_host_manager
    def uninstall(self, package_name):
        uninstall = '{0} remove {1} -y'.format(self.get_package_manager(),
                                              package_name)
        with settings(warn_only=True):
            return self.sudo(uninstall)

    def list_compilers(self):
        self.sudo("yum list installed '\gcc*\'")

    @server_host_manager
    def list_installed_package(self):
        self.run("yum list installed")


distro = os.environ.get("Distro", "Debian")

if distro == "RedHat":
    CurrentServer = RedHat
elif distro == "BSD":
    CurrentServer = BSD
else:
    CurrentServer = Debian
