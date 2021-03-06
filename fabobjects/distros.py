# coding: utf-8
from __future__ import with_statement

import os
import re
import socket
import datetime
import inspect
from os.path import join
from os import environ
from urllib.request import urlopen

from fabric.contrib.files import sed
from fabric.contrib.files import exists
from fabric.contrib.files import append
from fabric.contrib.files import comment
from fabric.contrib.files import uncomment
from fabric.utils import error
from fabric.api import sudo
from fabric.api import run
from fabric.api import reboot
from fabric.api import put
from fabric.api import get
from fabric.api import prompt
from fabric.api import hide
from fabric.api import cd
from fabric.api import lcd
from fabric.api import settings
from fabric.api import local
from fabric.colors import yellow
from fabric.colors import blue
from fabric.colors import red

from .settings import env_settings as env
from .utils import _print
from .utils import server_host_manager

now = str(datetime.datetime.now()).replace(" ", "-")
motd_file = os.path.join(os.getcwd(), "motd")

# stolen from cuisine
SHELL_ESCAPE = " '\";`|"


# stolen from cuisine
def shell_safe(path):
    """
    Makes sure that the given path/string is escaped and safe for shell
    :param string path:
    :return: string
    """
    return "".join([("\\" + _) if _ in SHELL_ESCAPE else _ for _ in path])


class BaseServer(object):
    """
    An SSH daemon connection.
    **Basics**
    This class performs useful high level operations over ssh.
    """

    def __init__(self, *args, **kwargs):
        """
        Initializes a server.

        :param dict env: A fabric env object or dict
        :param str ip: The IP address of this server
        :param str domain_name: The fqdn if you have one else set to None
        :param str hostname: The hostname of this server
        :param str email: Sysadmin email this is where your logs will me mailed to
        :param str user_ip: The IP address that will be used to connect to the server set this if you have fixed ip.
        :param str user: The username you will use to connect to the server
        :param int ssh_port: Your ssh port number
        :param str password: The password you will used to work on the server when promted for one.
        """
        self.cache = {}
        self.hostfile = "/etc/hosts"
        self.env = kwargs.get("env") or env
        self.ip = kwargs.get("ip")
        self._domain_name = kwargs.get("domain_name") or getattr(
            env, "domain_name", None
        )
        self._hostname = kwargs.get("hostname") or getattr(env, "hostname", None)
        self._email = kwargs.get("email", None)
        self.user_ip = kwargs.get("user_ip", None)
        self.user = kwargs.get("user") or env.user
        self.ssh_port = kwargs.get("ssh_port") or "22"
        self.password = kwargs.get("password", environ.get("PASSWORD", None))
        self._apps = []

    def __repr__(self):
        return "<{0}:{1}>".format(self.__class__.__name__, self._host)

    def __str__(self):
        return "{0}({1}@{2})".format(self.__class__.__name__, self.user, self._host)

    def __eq__(self, other):
        return all(
            [
                self.user == getattr(other, "user", None),
                self.ip == getattr(other, "ip", None),
                self.ssh_port == getattr(other, "ssh_port", None),
            ]
        )

    @server_host_manager
    def cd(self, *args, **kwargs):
        """A wrapper around Fabric's cd to change the local directory if
        mode is local"""
        if self.ip in ["127.0.0.1", "localhost"]:
            return lcd(*args, **kwargs)
        return cd(*args, **kwargs)

    @server_host_manager
    def create_app(self, AppClass, data=None):
        """
        Creates an application server from the
        :param class AppClass: An app class
        :return:
        """
        if data is None:
            data = {}

        attributes = ["cache", "env", "hostfile", "ip", "user", "ssh_port", "password"]
        ServerClass = self.__class__

        class Application(ServerClass, AppClass):
            """
            This is just a server class that get a base os and added new methods from the application class.
            """

            def __init__(self, *args, **kwargs):
                ServerClass.__init__(self, *args, **kwargs)
                super(Application, self).__init__(*args, **kwargs)

        hostname = self._hostname or self.hostname
        app = Application(domain_name=self._domain_name, hostname=hostname, **data)

        # Set all attributes of the host to the application so that we can control the host from the app and expose some
        #  of the server methods to the host.
        [setattr(app, att, getattr(self, att)) for att in attributes]
        return app

    def add_app(self, app):
        """
        Add and app to list of apps installed on server.
        :param app: App instance
        :return: None
        """
        if self == app and not hasattr(self, "deploy"):
            if app not in self._apps:
                self._apps.append(app)
        else:
            raise AttributeError

    def remove_app(self, app):
        """
        Remove an app from list of apps deployed on server.
        :param app: App instance
        :return: None
        """
        if self == app and not hasattr(self, "deploy"):
            if app in self._apps:
                self._apps.remove(app)
        else:
            raise AttributeError

    def list_apps(self):
        """
        List apps deployed on server.
        :return:
        """
        if not hasattr(self, "deploy"):
            return self._apps
        raise AttributeError

    def deploy_all(self):
        """
        Deploy all app added to server
        :return: None
        """
        if not hasattr(self, "deploy"):
            [app.deploy() for app in self._apps]
        else:
            raise AttributeError

    @classmethod
    def _list_funs(cls):
        """
        List all functions of this class
        :return: None
        """
        list_funcs = [i[0] for i in inspect.getmembers(cls) if not i[0].startswith("_")]
        return sorted([func for func in list_funcs])

    def getattribute(self, func, *args, **kwargs):
        """
        This method helps you call other instance methods and can accept args and kwargs mostly good for call private
        variables and methods.
        :param func: function
        :param args:
        :param kwargs:
        :return: function or None
        """
        if hasattr(self, func):
            if hasattr(getattr(self, func), "__call__"):
                return getattr(self, func)(*args, **kwargs)
            return getattr(self, func)
        return None

    def get_package_manager(self):
        """
        This will return the name of package manager on given os, example ubuntu should return apt or apt-get.
        :return: string
        """
        raise NotImplementedError

    @server_host_manager
    def get_installation_date(self):
        return " ".join(self.sudo("ls -lt /var/log/installer").split()[-4:-1])

    @property
    def get_password(self):
        with hide("running", "stdout"):
            if self.password is not None:
                return self.password
            name = "%s@%s" % (self.user, self.ip)
            passwords = self.env.passwords.get(name)
            return passwords

    @property
    def hostname(self):
        hostname = self.get_hostname()
        return hostname

    @property
    def _host(self):
        if self.ip in ["localhost", "127.0.0.1"]:
            return "127.0.0.1"

        if self.ssh_port != "22":
            host = "{0}@{1}:{2}".format(self.user, self.ip, self.ssh_port)
        else:
            host = "{0}@{1}".format(self.user, self.ip)
        return host

    @property
    def os_name(self):
        return self.run("lsb_release -a").split("\n")[1].split(":\t")[1].rstrip()

    @property
    def os(self):
        try:
            return self.run("lsb_release -a").split("\n")[0].split(":\t")[1].rstrip()
        except IndexError:
            return self.run("lsb_release -a").split("\n")[1].split(":\t")[1].rstrip()

    @server_host_manager
    def clear_screen(self):
        os.system("clear")

    @server_host_manager
    def ping(self):
        try:
            response = self.local("ping -c 4 {0}".format(self.ip), capture=True)
            ping_count = response.split("\n")[-2].split(", ")[1].split(" ")[0]

            if ping_count == "4":
                return "Pong"
            else:
                return
        except:
            return False

    @server_host_manager
    def kill_process_by(self, user=None):
        if user is None:
            user = self.run("whoami", show=False)
        self.sudo("killall -u {0}".format(user))

    @server_host_manager
    def install_package(self, package):
        manager = self.get_package_manager()
        command = "{0} install {1} -y".format(manager, package)
        with settings(warn_only=True):
            self.sudo(command)

    @server_host_manager
    def uninstall_package(self, package):
        uninstall = "{0} --purge remove {1} -y".format(
            self.get_package_manager(), package
        )
        with settings(warn_only=True):
            self.sudo(uninstall)
            self.sudo("apt-get autoremove")

    @server_host_manager
    def is_package_installed(self, package_name):
        """
        Returns True if a given package is install on os
        """
        with settings(warn_only=True):
            info = self.sudo("dpkg -s {0}".format(package_name))
            if info.split("\n")[1] == "Status: install ok installed\r":
                return True
            return False

    @server_host_manager
    def service(self, *args):
        cmd = " ".join([arg for arg in args])
        cmd = "service " + cmd
        return self.sudo(cmd)

    @server_host_manager
    def service_reload(self, service_name):
        self.service("{0} reload".format(service_name))

    @server_host_manager
    def service_start(self, service_name):
        self.service("{0} start".format(service_name))

    @server_host_manager
    def service_stop(self, service_name):
        self.service("{0} stop".format(service_name))

    @server_host_manager
    def service_restart(self, service_name):
        self.service("{0} restart".format(service_name))

    @server_host_manager
    def service_status(self, service_name):
        self.service("{0} status".format(service_name))

    @server_host_manager
    def list_files_with_no_owner(self, dir_name="/"):
        return self.sudo(
            "find {0} -xdev \( -nouser -o -nogroup \) -print".format(dir_name)
        )

    @server_host_manager
    def list_world_writable_files(self, dir_path="/"):
        return self.sudo(
            "find {0} -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print".format(
                dir_path
            )
        )

    @server_host_manager
    def free_inactive_memory(self):
        return self.sudo("sync; echo 3 | sudo tee /proc/sys/vm/drop_caches")

    @server_host_manager
    def used_memory(self):
        return self.current_memory_usage()[87:94].strip()

    @server_host_manager
    def sys_memory(self):
        return self.current_memory_usage()[76:83].strip()

    @server_host_manager
    def free_memory(self):
        return self.current_memory_usage()[98:105].strip()

    @server_host_manager
    def cpu_number(self):
        return self.sudo("grep processor /proc/cpuinfo | wc -l")

    @server_host_manager
    def install_bower(self):
        self.install_package("nodejs")
        self.install_package("npm")
        self.install_package("-g bower")
        self.sudo(
            "chown -R {user} /usr/local && ln -s /usr/bin/nodejs /usr/bin/node".format(
                user=self.user
            )
        )

    @server_host_manager
    def _get_home_dir(self, user=None):
        if user is None:
            user = self.run("whoami")
        output = self.sudo("grep {0} /etc/passwd | cut -d: -f6".format(user))
        return [host for host in filter(None, output.split())]

    @server_host_manager
    def show_public_key(self, key_path=None, user=None):
        if user is None:
            user = self.run("whoami")

        if key_path is None:
            home_dir = self._get_home_dir(user=user)[0]
            key_path = os.path.join(home_dir, ".ssh/id_rsa.pub")

        if not self.exists(key_path):
            self.create_ssh_key()
            self.show_public_key(key_path=key_path)

        command = "cat {0}".format(key_path)
        return self.run_as_user(command, user=user)

    @server_host_manager
    def generate_self_signed_ssl(
        self,
        domain="",
        cert_dir="/tmp/",
        country_iso="",
        state="",
        city="",
        company_name="",
    ):
        """
        Generate self-signed SSL certificates.
        """
        if not all([domain, country_iso, state, city, company_name]):
            raise KeyError

        full_cert_dir = os.path.join(cert_dir, "certs")

        if not self.exists("mkdir {0}".format(full_cert_dir)):
            self.sudo("mkdir -p {0}".format(full_cert_dir))

        with hide("everything"):
            with self.cd(full_cert_dir):
                self.sudo(
                    "openssl req -newkey rsa:2048 -nodes -keyout "
                    "{0}.key -x509 -days 365 -out {0}.crt "
                    "-subj '/C={1}/ST={2}/L={3}/O={4}/"
                    "CN={0}'".format(domain, country_iso, state, city, company_name)
                )
                self.sudo(
                    "chmod 640 {0}/{1}.key {0}/{1}.crt".format(full_cert_dir, domain)
                )
            return full_cert_dir

    @server_host_manager
    def disable_root_login(self):
        """
        Disable `root` login for even more security. Access to `root` account
        is now possible by first connecting with your dedicated maintenance
        account and then running ``sudo su -``.
        """
        self.sudo("passwd --lock root")

    @server_host_manager
    def fqdn(self, domain_name=None, hostname=None, fqdn=True):
        if not any([domain_name, self._domain_name]):
            raise RuntimeError("Your Server has no domain name and none entered")

        if not any([hostname, self._hostname]):
            raise RuntimeError("Your Server has no hostname and none entered")

        if self._domain_name is None:
            domain_name = domain_name or self._domain_name

        if self._hostname is None:
            hostname = hostname or self._hostname

        fqdn_ = "{0}.{1}".format(hostname, domain_name)

        if fqdn:
            return fqdn_

        return hostname, domain_name, fqdn_

    @server_host_manager
    def __set_kernel_domain_name(self, domain_name=None, hostname=None):
        if domain_name is not None:
            full_domain_name = self.fqdn(hostname=hostname, domain_name=domain_name)

            if all([full_domain_name, domain_name, hostname]):
                self.echo(
                    domain_name,
                    to="/proc/sys/kernel/domainname",
                    use_sudo=True,
                    append=False,
                )
                self.echo(
                    hostname,
                    to="/proc/sys/kernel/hostname",
                    use_sudo=True,
                    append=False,
                )

                afile = "/etc/sysctl.conf"
                self.echo(
                    "kernel.hostname={0}".format(hostname),
                    to=afile,
                    use_sudo=True,
                    append=True,
                )
                self.echo(
                    "kernel.domainname={0}".format(domain_name),
                    to=afile,
                    use_sudo=True,
                    append=True,
                )
                return full_domain_name
            raise RuntimeError(
                "Your server has no domain name or hostname and none entered"
            )

    @server_host_manager
    def __set_hostname(self, hostname=None, domain_name=None):
        """Set server's hostname."""
        opts = dict(public_ip=self.ip, hostname=hostname)

        if domain_name is not None:
            opts.update({"domainname": domain_name})

        afile = self.hostfile
        self.echo("127.0.0.1   localhost", to=afile, append=False)

        if domain_name is not None:
            self.echo(
                "127.0.1.1   %(hostname)s.%(domainname)s %(hostname)s" % opts, to=afile
            )
            self.echo(
                "%(public_ip)s  %(hostname)s.%(domainname)s %(hostname)s" % opts,
                to=afile,
            )

        self.echo(
            "# The following lines are desirable for IPv6 capable hosts", to=afile
        )
        self.echo("::1     ip6-localhost ip6-loopback", to=afile)
        self.echo("fe00::0 ip6-localnet", to=afile)
        self.echo("ff00::0 ip6-mcastprefix", to=afile)
        self.echo("ff02::1 ip6-allnodes", to=afile)
        self.echo("ff02::2 ip6-allrouters", to=afile)

        afile = "/etc/hostname"
        self.echo("%(hostname)s" % opts, to=afile)

    @server_host_manager
    def set_host(self, hostname=None, domain_name=None):
        if all([hostname, domain_name]):
            fqdn = self.fqdn(hostname=hostname, domain_name=domain_name)

            if all([hostname, domain_name]):
                self.__set_kernel_domain_name(
                    hostname=hostname, domain_name=domain_name
                )
                self.__set_hostname(hostname=hostname, domain_name=domain_name)
                self.sudo("hostname {0}".format(hostname))
                return True
        raise RuntimeError("Your Server has no domain name or hostname.")

    @server_host_manager
    def change_named_servers(self, ns1="208.67.222.222", ns2="208.67.220.220"):
        text_before = "dns-nameservers 8.8.8.8 8.8.4.4"
        text_after = "dns-nameservers {0} {1}".format(ns1, ns2)

        try:
            self.sed("/etc/network/interfaces", text_before, text_after, use_sudo=True)
        except:
            self.echo(text_before, "/etc/network/interfaces", use_sudo=True)

    @server_host_manager
    def ip_spoofing_guard(self):
        # Guard against spoof attempts
        self.echo("nospoof:  on", to="/etc/nsswitch.conf", use_sudo=True, append=True)

    @server_host_manager
    def limit_sudo_users(self, user_group="admin"):
        if user_group not in self.list_groups():
            self.sudo("groupadd {0}".format(user_group))

        self.sudo("usermod -a -G {0} {1}".format(user_group, self.user))
        self.sudo(
            "dpkg-statoverride --update --add root {0} 4750 /bin/su".format(user_group)
        )

    @server_host_manager
    def harden_host_files(self, hosts_allowed=None):
        hosts_allowed = hosts_allowed or []
        # Back up files
        self.echo("umask 077", to="/etc/bash.bashrc", use_sudo=True, append=True)
        self.sudo("cp /etc/hosts.allow /etc/hosts.allow.backup.{now}".format(now=now))
        self.sudo("cp /etc/hosts.deny /etc/hosts.deny.backup.{now}".format(now=now))

        for host in hosts_allowed:
            if host != self.ip:
                self.sudo("echo 'sshd: {host}\n' >> /etc/hosts.allow".format(host=host))
        self.echo("ALL: PARANOID", to="/etc/hosts.deny", use_sudo=True, append=True)

    @server_host_manager
    def other_sys_security(self):
        self.echo("umask 077", to="/etc/bash.bashrc", use_sudo=True, append=True)
        self.sed(
            "/etc/login.defs", "UMASK        022", "UMASK        077", use_sudo=True
        )
        self.sed(
            "/etc/login.defs",
            "PASS_MAX_DAYS    99999",
            "PASS_MAX_DAYS 60",
            use_sudo=True,
        )
        self.sed(
            "/etc/login.defs", "PASS_WARN_AGE    7", "PASS_WARN_AGE 5", use_sudo=True
        )
        self.sed(
            "/etc/login.defs",
            "DEFAULT_HOME    yes",
            "DEFAULT_HOME    no",
            use_sudo=True,
        )
        self.echo("SHA_CRYPT_MIN_ROUNDS 5000", to="/etc/login.defs")
        self.echo("SHA_CRYPT_MAX_ROUNDS 10000", to="/etc/login.defs", use_sudo=True)

        afile = "/etc/pam.d/common-session"
        self.echo(
            "password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512 remember=12",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "password required pam_cracklib.so retry=3 minlen=12 difok=3 ucredit=-1 ocredit=-1",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "password requisite pam_deny.so", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "password required pam_permit.so", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "password optional pam_ecryptfs.so", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "session optional    pam_umask.so umask=027",
            to=afile,
            use_sudo=True,
            append=True,
        )

        afile = "/etc/profile"
        self.echo("umask 077", to=afile, use_sudo=True, append=True)

        afile = "/etc/security/limits.conf"
        self.echo("*  hard core 0", to=afile, use_sudo=True, append=True)
        self.echo("* soft nproc 100", to=afile, use_sudo=True, append=True)
        self.echo("* hard nproc 150", to=afile, use_sudo=True, append=True)

        afile = "/etc/sysctl.conf"
        self.echo("fs.suid_dumpable = 0", to=afile, use_sudo=True, append=True)

        afile = "/proc/sys/net/ipv4/ip_local_port_range"
        self.echo("1024 65535", to=afile)

    @server_host_manager
    def harden_sshd(self):
        """Security harden ssh server."""
        user = self.user
        self.add_sshgroup(user=user)
        users = self.list_users()

        if "git" in users:
            ssh_users = "sshuser git"
        else:
            ssh_users = "sshuser"

        self.sudo(
            "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.{now}".format(now=now)
        )

        # start a fresh remove all current entries
        self.sudo("echo 'AllowGroups {0}' > /etc/ssh/sshd_config".format(ssh_users))
        self.sudo("echo 'AllowTcpForwarding no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'Port 22' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'Protocol 2' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'HostKey /etc/ssh/ssh_host_rsa_key' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'HostKey /etc/ssh/ssh_host_dsa_key' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'HostKey /etc/ssh/ssh_host_ecdsa_key' >>  /etc/ssh/sshd_config")
        self.sudo(
            "echo 'HostKey /etc/ssh/ssh_host_ed25519_key' >>  /etc/ssh/sshd_config"
        )
        self.sudo("echo 'UsePrivilegeSeparation yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'KeyRegenerationInterval 3600' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'ServerKeyBits 1024' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'SyslogFacility AUTH' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'LogLevel INFO' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'LoginGraceTime 20' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'MaxAuthTries 3' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'PermitRootLogin no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'StrictModes yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'RSAAuthentication yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'PubkeyAuthentication yes' >>  /etc/ssh/sshd_config")
        self.sudo(
            "echo 'AuthorizedKeysFile %h/.ssh/authorized_keys' >>  /etc/ssh/sshd_config"
        )
        self.sudo("echo 'IgnoreRhosts yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'RhostsRSAAuthentication no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'HostbasedAuthentication no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'PermitEmptyPasswords no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'PasswordAuthentication no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'X11Forwarding no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'X11DisplayOffset 10' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'PrintMotd no' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'PrintLastLog yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'TCPKeepAlive yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'ClientAliveInterval 300' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'ClientAliveCountMax 0' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'MaxStartups 3:50:10' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'AcceptEnv LANG LC_*' >>  /etc/ssh/sshd_config")
        self.sudo(
            "echo 'Subsystem sftp /usr/lib/openssh/sftp-server' >>  /etc/ssh/sshd_config"
        )
        self.sudo("echo 'UsePAM yes' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'Compression delayed' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'ListenAddress 0.0.0.0' >>  /etc/ssh/sshd_config")
        self.sudo("echo 'GSSAPIAuthentication no' >>  /etc/ssh/sshd_config")

    @server_host_manager
    def tune_network_stack(self):
        afile = "/etc/sysctl.d/10-network-security.conf"
        self.echo(
            "net.ipv4.conf.default.rp_filter=1", to=afile, use_sudo=True, append=True
        )
        self.echo("net.ipv4.conf.all.rp_filter=1", to=afile, use_sudo=True, append=True)
        self.echo("net.ipv4.tcp_syncookies=1", to=afile, use_sudo=True, append=True)
        self.echo(
            "net.ipv6.conf.all.forwarding=0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.conf.all.accept_redirects=0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv6.conf.all.accept_redirects=0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv6.conf.all.accept_source_route=0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.tcp_max_syn_backlog = 4096", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.conf.all.accept_source_route = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.conf.all.secure_redirects = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.conf.default.accept_source_route = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.conf.default.accept_redirects = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.conf.default.secure_redirects = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.icmp_echo_ignore_broadcasts = 1",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo("net.ipv4.ip_forward = 0", to=afile, use_sudo=True, append=True)
        self.echo(
            "net.ipv4.conf.all.send_redirects = 0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.conf.default.send_redirects = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.accept_ra=0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv6.conf.default.accept_redirect=0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.router_solicitations = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.accept_ra_rtr_pref = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.accept_ra_pinfo = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.accept_ra_defrtr = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.autoconf = 0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv6.conf.default.dad_transmits = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv6.conf.default.max_addresses = 1",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.ip_local_port_range = 1024 65535",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.conf.all.mc_forwarding=0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.conf.all.forwarding=0", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.tcp_wmem = 10240 87380 12582912",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.tcp_window_scaling = 1", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.core.netdev_max_backlog = 5000", to=afile, use_sudo=True, append=True
        )
        self.echo("net.ipv4.tcp_fin_timeout=5", to=afile, use_sudo=True, append=True)
        self.echo("net.ipv4.tcp_timestamps = 1", to=afile, use_sudo=True, append=True)
        self.echo(
            "net.ipv4.tcp_no_metrics_save = 1", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.conf.all.log_martians = 1", to=afile, use_sudo=True, append=True
        )
        self.echo("net.core.wmem_max = 12582912", to=afile, use_sudo=True, append=True)
        self.echo("net.ipv4.tcp_syn_retries = 5", to=afile, use_sudo=True, append=True)
        self.echo(
            "net.ipv4.tcp_rmem = 10240 87380 12582912",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo("net.core.rmem_max = 12582912", to=afile, use_sudo=True, append=True)
        self.echo(
            "net.ipv6.conf.default.accept_redirects = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.icmp_ignore_bogus_error_responses = 1",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo(
            "net.ipv4.tcp_synack_retries = 2", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv4.icmp_echo_ignore_all = 1", to=afile, use_sudo=True, append=True
        )
        self.echo(
            "net.ipv6.conf.default.accept_source_route = 0",
            to=afile,
            use_sudo=True,
            append=True,
        )
        self.echo("net.ipv4.tcp_sack = 1", to=afile, use_sudo=True, append=True)
        self.sudo("sysctl -p")

    @server_host_manager
    def check_opened_ports(self):
        self.run("netstat -tulpn")

    @server_host_manager
    def install_fail2ban(self):
        """Install fail2ban"""
        self.install_package("fail2ban")
        self.sudo("cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local")

    @server_host_manager
    def install_denyhosts(self):
        self.install_package("denyhosts")

    @server_host_manager
    def install_psad(self):
        self.install_package("psad")
        self.sudo("iptables -A INPUT -j LOG")
        self.sudo("iptables -A FORWARD -j LOG")
        self.sudo("ip6tables -A INPUT -j LOG")
        self.sudo("ip6tables -A FORWARD -j LOG")
        self.sudo("psad -R")
        self.sudo("psad --sig-update")
        self.sudo("service psad restart")

    @server_host_manager
    def move_user_2_restricted_shell(self, user):
        self.sudo("usermod -s /usr/bin/rssh {0}".format(user))
        self.sudo("chsh -s /usr/bin/rssh {0}".format(user))

    @server_host_manager
    def setup_motd(self, motd_file=motd_file):
        """This is message that displays when you login to ssh."""
        with open(motd_file) as _file:
            file_content = _file.read()

        if self.exists("/etc/motd"):
            self.sudo("cp /etc/motd /etc/motd.old", quiet=True)
            self.echo(
                " '{}' ".format(file_content),
                to="/etc/motd",
                use_sudo=True,
                append=False,
            )

        if self.exists("/etc/issue.net"):
            self.sudo("cp /etc/issue.net /etc/issue.net.old", quiet=True)
            self.echo(
                " '{}' ".format(file_content),
                to="/etc/issue.net",
                use_sudo=True,
                append=False,
            )

    @server_host_manager
    def install_rkhunter_n_chkrootkit(self, email):
        self.install_postfix()
        self.install_package("rkhunter chkrootkit")
        self.sudo("cp /etc/chkrootkit.conf /etc/chkrootkit.conf.backup")
        self.sudo("cp /etc/default/rkhunter /etc/default/rkhunter.backup")
        self.sudo("echo > /etc/default/rkhunter")
        self.sudo("echo > /etc/chkrootkit.conf")
        self.sudo("echo \"RUN_DAILY='true'\" >> /etc/chkrootkit.conf")
        self.sudo("echo \"RUN_DAILY_OPTS=''\" >> /etc/chkrootkit.conf")
        self.sudo("echo \"CRON_DAILY_RUN='true'\" >> /etc/default/rkhunter")
        self.sudo("echo \"CRON_DB_UPDATE='true'\" >> /etc/default/rkhunter")
        # update files properties DB every time you run apt-get install, this
        # prevents warnings every time a new version of some package is installed
        self.append(
            "/etc/default/rkhunter",
            "# Update file properties database after running apt-get install",
            use_sudo=True,
        )
        self.append("/etc/default/rkhunter", 'APT_AUTOGEN="yes"', use_sudo=True)

        # ignore some Ubuntu specific files
        self.sudo("mkdir -p ~/bin")

        with self.cd("~/bin"):
            self.sudo('echo "#!/bin/sh" >> rkhunterscript')
            self.sudo(
                'echo "/usr/local/bin/rkhunter --versioncheck \
             /usr/local/bin/rkhunter --update /usr/local/bin/rkhunter \
              --cronjob --report-warnings-only | /usr/bin/mail \
                -s "rkhunter output" {0}" >> rkhunterscript'.format(
                    email
                )
            )
            self.sudo("chmod 750 rkhunterscript")
            self.sudo('echo "10 3 * * * rkhunterscript -c --cronjob" >> mycron')
            self.sudo("crontab mycron")
        self.rkhunter_scan()

    @server_host_manager
    def rkhunter_scan(self):
        self.sudo("chkrootkit")
        self.sudo("rkhunter --update")
        self.sudo("rkhunter --propupd")
        self.sudo("yes Y | sudo rkhunter --check --ns")

    @server_host_manager
    def setup_logwatch(self, email):
        """Install and Configure Log watch."""
        with settings(warn_only=True):
            self.install_package("logwatch")
            self.sudo("mkdir /var/cache/logwatch")
            self.sudo(
                "cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf"
            )

        self.sed(
            "/etc/logwatch/conf/logwatch.conf",
            "Range = yesterday",
            "Range = between -7 days and -1 days",
            use_sudo=True,
        )

        self.sed(
            "/etc/logwatch/conf/logwatch.conf",
            "Output = stdout",
            "Output = mail",
            use_sudo=True,
        )

        self.sed(
            "/etc/logwatch/conf/logwatch.conf",
            "Format = text",
            "Format = html",
            use_sudo=True,
        )

        self.sed(
            "/etc/logwatch/conf/logwatch.conf",
            "MailTo = root",
            "MailTo = {0}".format(email),
            use_sudo=True,
        )

        self.sed(
            "/etc/logwatch/conf/logwatch.conf",
            "Detail = Low",
            "Detail = Med",
            use_sudo=True,
        )

        self.sudo("echo \"Service = '-denyhosts'\" >> /etc/logwatch/conf/logwatch.conf")
        self.sudo('echo "Service = "-exim"" >> /etc/logwatch/conf/logwatch.conf')
        with settings(warn_only=True):
            self.sudo("cp /etc/cron.daily/00logwatch /etc/cron.weekly/00logwatch")
        self.sudo("echo 'in.telnetd: ALL' >> /etc/hosts.deny")
        self.sudo("echo 'in.ftpd: ALL' >> /etc/hosts.deny")

    @server_host_manager
    def install_apparmor(self):
        self.install_package("apparmor apparmor-profiles")
        self.sudo("apparmor_status")

    @server_host_manager
    def set_up_tiger(self):
        self.install_package("tiger")
        self.sudo("tiger")

    @server_host_manager
    def view_tiger_report(self):
        self.sudo("less /var/log/tiger/security.report.*")

    def find_broken_symblinks_delete(self):
        self.sudo("find -L /path/to/check -type l -delete")
        self.sudo("chmod go-w /bin/cp")
        self.sudo("chmod -R go-rwx /root")

    @server_host_manager
    def harden_server(self, passwd=None, user_ip=None, email=None, motd_file=motd_file):
        email = email or self._email
        user_ip = user_ip or self.user_ip
        passwd = passwd or self.password

        if self.user == "root":
            raise RuntimeError("User can not be none or root")

        if not all([passwd, user_ip, motd_file, email]):
            raise RuntimeError("You have to pass in all needed variables")

        self.disable_root_login()
        self.harden_sshd()
        self.enable_process_accounting()
        self.setup_motd(motd_file=motd_file)

        # Lets update or system first
        self.update()
        self.remove_old_kernels()
        self.change_named_servers()
        self.set_host(hostname=self._hostname, domain_name=self._domain_name)
        self.tune_network_stack()
        self.harden_host_files()
        self.ip_spoofing_guard()
        self.secure_shared_memory()
        self.other_sys_security()
        self.limit_sudo_users()
        self.locale_conf()
        self.set_system_time()
        self.install_package("libpam-tmpdir libpam-cracklib debconf-utils")
        self.install_postfix()
        self.install_apparmor()
        self.install_fail2ban()
        self.setup_logwatch(email=email)
        self.install_rkhunter_n_chkrootkit(email)
        self.clean_manager()
        self.install_firewall(user_ip=user_ip)  # Create firewall

    @server_host_manager
    def get_hostname(self):
        hostname = self.cache.get("hostname")
        if not hostname:
            with hide("running", "stdout"):
                hostname = self.run("hostname -f")
                if hostname:
                    self.cache["hostname"] = hostname
        return hostname

    @server_host_manager
    def get_internal_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("gmail.com", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    @server_host_manager
    def get_public_ip(self):
        data = str(urlopen("http://checkip.dyndns.com/").read())
        return re.compile(r"Address: (\d+\.\d+\.\d+\.\d+)").search(data).group(1)

    @server_host_manager
    def set_system_time(self, timezone="UTC"):
        """Set timezone and install ``ntp`` to keep time accurate."""
        if timezone is not None:
            timezone = "/usr/share/zoneinfo/{0}".format(timezone)
        opts = dict(timezone=timezone or env.get("timezone"))

        self.sudo("ln -sf {timezone}s /etc/localtime".format(**opts))  # set timezone
        self.install_package("ntp")  # install NTP

    @server_host_manager
    def locale_conf(self, locale="en_IE.UTF-8"):
        self.sudo("locale-gen --purge en_US.UTF-8")
        self.sudo("locale-gen {0}".format(locale))
        self.sudo("dpkg-reconfigure -f noninteractive locales")

    def local_user_home(self):
        return self.local("eval echo ~$USER", capture=True)

    @server_host_manager
    def create_user(self, user, home=None, passwd=None, no_home=False):
        """Create new user account."""
        if user is None:
            error("User was not provided")

        if user in self.list_users():
            self._print("User already exist")
            return True

        if home is None:
            home = "/home/{0}".format(user)

        if no_home:
            command = "useradd {0}".format(user)

        else:
            command = "useradd -m -d {0} {1}".format(home, user)

        if passwd is not None:
            command = command.replace("useradd", "useradd -p {0}".format(passwd))

        with hide("running", "stdout", "stderr"):
            self.sudo(command, show=False)

    @server_host_manager
    def change_password(self, user, pswd):
        """Change user account password."""
        with hide("running", "stdout", "stderr"):
            self.sudo('echo "{0}:{1}" | chpasswd'.format(user, pswd))

    @server_host_manager
    def delete_user(self, user, home=False):
        command = "userdel -r {0}".format(user) if home else "userdel {0}".format(user)
        self.sudo(command)

    @server_host_manager
    def create_restricted_user(self, user, passwd, home=None, shell=True):
        """Create user with limited shell access."""
        if home is None:
            home = "/home/{0}".format(user)

        self.sudo(
            "useradd -m -p {2} -d {0} -s /usr/bin/rssh {1}".format(home, user, passwd)
        )
        self.sudo("passwd {0}".format(user))

        if shell:
            with self.cd(home):
                with settings(user=user):
                    self.create_ssh_key()

    @server_host_manager
    def add_sshgroup(self, user=None):
        if user is None:
            user = self.user

        with settings(warn_only=True):
            if "sshuser" not in self.list_groups():
                self.sudo("addgroup sshuser")

            if "sshuser" not in self.list_user_groups(user=user):
                self.sudo("adduser {user} sshuser".format(user=user))

    @server_host_manager
    def create_admin_account(self, admin_username, admin_password):
        """Create the admin group and add it to the sudoers file."""
        if not self.is_package_installed("sudo"):
            self.install_package("sudo")

        with settings(warn_only=True):
            admin_group = "admin"
            if admin_group not in self.list_groups():
                self.sudo("addgroup {group}".format(group=admin_group))
                self.sudo(
                    'echo "{group} ALL=(ALL) ALL" >> /etc/sudoers'.format(
                        group=admin_group
                    )
                )

        with settings(warn_only=True):
            # Create the new admin user (default group=username); add to admin group
            if admin_username not in self.list_users():
                self.sudo(
                    'adduser {username} --disabled-password --gecos ""'.format(
                        username=admin_username
                    )
                )
                self.sudo(
                    "adduser {username} {group}".format(
                        username=admin_username, group=admin_group
                    )
                )
                self.sudo(
                    'echo "{username} ALL=(ALL) ALL" >> /etc/sudoers'.format(
                        username=admin_username
                    )
                )
                self.change_password(admin_username, admin_password)
                self.add_sshgroup(user=admin_username)
                self.send_ssh(admin_username)
                self.user = admin_username
                self.password = admin_password

    @server_host_manager
    def add_user_to_sudo(self, user):
        """Add a user to the sudoer file."""
        if "sudo" in self.list_user_groups(user=user):
            self._print("User already in sudo group")
            return True

        with settings(warn_only=True):
            self.sudo("adduser %s sudo" % user)

    @server_host_manager
    def current_kernel(self):
        result = self.run("uname -a")
        return result

    @server_host_manager
    def current_memory_usage(self):
        return self.sudo("free -hm")

    @server_host_manager
    def uptime(self):
        return self.sudo("uptime")

    @server_host_manager
    def get_hard_drive_info(self):
        self.sudo("dmidecode -t 17")

    @server_host_manager
    def get_top_resource_users(self):
        self.run("ps -eo pcpu,pid,user | sort -k 1 -r | head -6")

    @server_host_manager
    def get_memory_use(self):
        self.run("ps -eo pmem,pid,user | sort -k 1 -r | head -6")

    @server_host_manager
    def list_users_short_version(self):
        result = self.run("ps aux | awk '{ print $1 }' | sed '1 d' | sort | uniq")
        return sorted(result.split())

    @server_host_manager
    def list_users(self):
        result = self.run("cut -d: -f 1 /etc/passwd")
        return sorted(result.split())

    @server_host_manager
    def list_groups(self):
        result = self.run("cut -d: -f 1 /etc/group")
        return sorted(result.split())

    @server_host_manager
    def list_user_groups(self, user):
        groups = self.run_as_user("groups", user=user).split()
        return groups

    @server_host_manager
    def get_general_info(self):
        """Retrieve hostname and some general server info"""
        self.run("hostname")
        self.run("df -h")
        self.run("free -m")

    @server_host_manager
    def remove_old_kernels(self):
        with settings(warn_only=True):
            self.sudo(
                "dpkg -l linux-* | awk '/^ii/{ print $2}' | grep -v -e `uname -r | cut -f1,2 -d\"-\"` "
                '| grep -e [0-9] | grep -E "(image|headers)" | xargs sudo apt-get -y purge'
            )

    @server_host_manager
    def shutdown(self):
        return self.sudo("shutdown -r now")

    @server_host_manager
    def rebootall(self):
        return reboot()

    @server_host_manager
    def update(self):
        manager = self.get_package_manager()
        self.sudo("{0} update".format(manager))
        self.sudo("{0} upgrade -y".format(manager))
        self.sudo("{0} autoremove -y".format(manager))

    def create_symbolic_link(self, link_from, link_to):
        """
        Create a symbolic link
        :param str link_from: The initial link
        :param link_to: File/fold linked to
        :return: None
        """
        return self.sudo("ln -s {0} {1}".format(link_from, link_to))

    def uncompress(self, file_path, output_dir=None, file_type="tar"):
        """
        Uncompress tar or zip files or folder
        :param file_path: The input file
        :param output_dir: The output file
        :param file_type: type if its zip or tar
        :return: None
        """
        if output_dir is None:
            base = "/".join([path for path in filter(None, file_path.split("/")[:-1])])
            output_dir = "/{0}".format(base)

        if file_type == "tar":
            return self.sudo("tar xvzf -C {0} {1}".format(output_dir, file_path))

        if file_type == "zip":
            return self.sudo("unzip {0} {1}".format(output_dir, file_path))
        raise TypeError

    def compress(self, input_file, output_file=None, file_type="tar"):
        """
        Compress tar or zip files or folder
        :param input_file: The input file
        :param output_file: The output file
        :param file_type: type if its zip or tar
        :return: None
        """
        if output_file is None:
            base = "/".join([path for path in filter(None, input_file.split("/")[:-1])])
            file_name = input_file.split("/")[-1]
            output_file = f"/{base}/{file_name}.tar.gz"

        if file_type == "tar":
            return self.sudo("tar -czvf {0}.tat.gz {1}".format(input_file, output_file))

        if file_type == "zip":
            return self.sudo("zip -r {0} {1}".format(output_file, input_file))
        raise TypeError

    @server_host_manager
    def make_or_del(
        self, path, make=True, use_sudo=False, verbose=False, is_file=False
    ):
        """makes or delete a remote path if it exist/not exist"""
        command = "sudo" if use_sudo else "run"
        if is_file:
            action = "touch  " if make else "rm -rf "
        else:
            action = "mkdir -p " if make else "rm -r -rf "
        if self.exists(path, use_sudo=use_sudo, verbose=verbose):
            if not make:
                getattr(self, command)(action + path)
            else:
                print("path:{0} not created it already exist".format(path))
        else:
            if make:
                getattr(self, command)(action + path)
            else:
                print("path:{0} not delete as path dose not exist".format(path))

    @server_host_manager
    def clone_repo(self, repo):
        self.run("git clone {0}".format(repo))

    @server_host_manager
    def create_n_put_keys(self):
        self.create_ssh_key()
        self.push_key()
        self.service_restart("ssh")

    @server_host_manager
    def user_lastcomm(self):
        self.sudo("lastcomm")

    @server_host_manager
    def echo(self, command, to="", use_sudo=True, append=True):
        run_with = self.sudo if use_sudo else self.run
        append = ">>" if append else ">"
        if to:
            run_with("echo {0}  {1} {2}".format(command, append, to))
        else:
            run_with("echo {0}".format(command))

    @server_host_manager
    def secure_shared_memory(self):
        self.sudo(
            "echo 'tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0' >>  /etc/fstab"
        )

    @server_host_manager
    def firewall_status(self):
        self.sudo("ufw status verbose")

    @server_host_manager
    def view_firewall_rules(self):
        return self.sudo("ufw status numbered")

    @server_host_manager
    def firewall_allow_form_to(self, host=None, proto="tcp", port="22"):
        if all([host, proto, port]):
            self.sudo(
                "ufw allow from {0} proto {1} to any port {2}".format(host, proto, port)
            )
        else:
            print("Invalid host or port entered")

    @server_host_manager
    def delete_firewall_number(self, num):
        self.sudo("yes Y | ufw delete {0}".format(str(num)))

    @server_host_manager
    def configure_firewall(self, rules=None, enable=True):
        """Configure Firewall."""
        if not rules or rules is None:
            error("rules must be set")

        [self.sudo(rule) for rule in rules]

        # re-enable firewall
        if enable:
            self.sudo("yes Y | ufw enable")

        self.sudo("ufw status verbose")

    @server_host_manager
    def install_firewall(self, user_ip=None, port="22"):
        """Install and configure Uncomplicated Firewall."""

        if user_ip is None:
            raise RuntimeError("please Enter your Ip address")

        self.install_package("ufw")
        self.sudo("yes Y | ufw reset")

        default_rules = [
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw limit ssh",
        ]

        allow_from = getattr(self.env, "ssh_allowed", [])

        if type(user_ip) == list:
            allow_from.extend(user_ip)
        else:
            allow_from.append(user_ip)

        allow_from = list(set(allow_from))

        if allow_from:
            for host in allow_from:
                default_rules.append(
                    "ufw allow from {0} proto tcp to any port {1}".format(host, port)
                )

        if self.is_package_installed("bind9"):
            default_rules.append("ufw allow 53")

        if getattr(self.env, "rules", None) is not None:
            default_rules.extend(list(set(self.env.rules)))

        self.configure_firewall(rules=default_rules, enable=False)

        self.view_firewall_rules()

    @server_host_manager
    def push_key(self):
        """Push user's ssh-key to server."""
        key_file = "/tmp/%s.pub" % env.user
        if self.exists(key_file, use_sudo=False, verbose=False):
            self.run("rm %s" % key_file)

        if not self.exists("~/.ssh", use_sudo=False, verbose=False):
            self.create_ssh_key()

        self.put(local_path="~/.ssh/id_rsa.pub", remote_path=key_file)
        self.run("cat {0} >> ~/.ssh/authorized_keys".format(key_file))
        self.run("chmod 600 ~/.ssh/authorized_keys")
        self.run("rm %s" % key_file)

    @server_host_manager
    def create_ssh_key(self):
        self.run("mkdir .ssh")
        self.run("chmod 700 .ssh")
        self.run('ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""')
        self.run("chmod 600 .ssh/id_rsa")
        self.run("touch .ssh/authorized_keys")
        self.run("chmod 600 .ssh/authorized_keys")

    @server_host_manager
    def generate_ssh(self, ssh_dir=None, pswd=None, user=None, restart=False):

        home_dir = self._get_home_dir(user=user)[0]

        if ssh_dir is None:
            ssh_dir = join(home_dir, ".ssh")

        rsa = join(ssh_dir, "id_rsa")

        if self.exists(rsa, use_sudo=True):
            print("rsa key exists, skipping creating")

        else:
            authorized_keys = join(ssh_dir, "authorized_keys")

            self.run_as_user("mkdir -p %s" % ssh_dir, user=user)
            self.run_as_user("chmod 700 %s" % ssh_dir, user=user)
            self.run_as_user("touch %s" % authorized_keys, user=user)
            self.run_as_user("chmod 600 %s" % authorized_keys, user=user)

            with hide("everything"):
                self.sudo("chown -R {0}. {1}".format(user, ssh_dir))
                command = "ssh-keygen -t rsa -b 4096 -f {0} -N {1}".format(rsa, pswd)

                if not user:
                    return self.run_as_app_user(command)
                else:
                    self.sudo(command, user=user)

        if restart:
            self.service_restart("ssh")

    @server_host_manager
    def enable_process_accounting(self):
        self.install_package("acct")
        self.sudo("touch /var/log/wtmp")

    @server_host_manager
    def users_connect_times(self):
        self.sudo("ac")

    @server_host_manager
    def users_previous_commands(self):
        self.sudo("sa")

    @server_host_manager
    def _print(self, output):
        _print(output)

    @server_host_manager
    def print_command(self, command):
        self._print(
            blue("$ ", bold=True) + yellow(command, bold=True) + red(" ->", bold=True)
        )

    @server_host_manager
    def run(self, command, show=True, **kwargs):
        """ Runs a shell command on the remote server. """
        if show:
            self.print_command(command)
        with hide("running"):
            if self.ip in ["localhost", "127.0.0.1"]:
                kwargs["capture"] = kwargs.get("capture", True)
                return local(command, **kwargs)
            return run(command, **kwargs)

    @server_host_manager
    def append(
        self,
        filename,
        text,
        show=True,
        use_sudo=False,
        partial=False,
        escape=True,
        shell=False,
    ):
        if show:
            self.print_command(text)
        with hide("running"):
            return append(
                filename,
                text,
                use_sudo=use_sudo,
                partial=partial,
                escape=escape,
                shell=shell,
            )

    @staticmethod
    def local(command, capture=True, shell=None):
        """Run a command on the local system."""
        return local(command, capture=capture, shell=shell)

    @server_host_manager
    def sudo(self, command, show=True, **kwargs):
        """ Runs a shell command on the remote server. """
        if show:
            self.print_command(command)
        with hide("everything"):
            if self.ip in ["localhost", "127.0.0.1"]:
                command = "sudo " + command
                return local(command, **kwargs)
            return sudo(command, **kwargs)

    @server_host_manager
    def exists(self, path, use_sudo=False, verbose=False):
        """
        Return True if given path exists on the current remote host.

        If ``use_sudo`` is True, will use `sudo` instead of `run`.

        `exists` will, by default, hide all output (including the run line, stdout,
        stderr and any warning resulting from the file not existing) in order to
        avoid cluttering output. You may specify ``verbose=True`` to change this
        behavior.
        """
        return exists(path, use_sudo=use_sudo, verbose=verbose)

    @server_host_manager
    def comment(
        self, filename, regex, use_sudo=False, char="#", backup=".bak", shell=False
    ):
        with hide("running"):
            comment(
                filename,
                regex,
                use_sudo=use_sudo,
                char=char,
                backup=backup,
                shell=shell,
            )

    @server_host_manager
    def uncomment(
        self, filename, regex, use_sudo=False, char="#", backup=".bak", shell=False
    ):
        with hide("running"):
            uncomment(
                filename,
                regex,
                use_sudo=use_sudo,
                char=char,
                backup=backup,
                shell=shell,
            )

    # stolen from cuisine
    @server_host_manager
    def dir_exists(self, location):
        """Tells if there is a remote directory at the given location."""
        return self.run(
            "test -d %s && echo OK ; true" % (shell_safe(location))
        ).endswith("OK")

    # stolen from cuisine
    @server_host_manager
    def dir_ensure(self, location, recursive=False, mode=None, owner=None, group=None):
        """Ensures that there is a remote directory at the given location,
        optionally updating its mode/owner/group.

        If we are not updating the owner/group then this can be done as a single
        ssh call, so use that method, otherwise set owner/group after creation."""
        if not self.dir_exists(location):
            self.run("mkdir %s %s" % (recursive and "-p" or "", shell_safe(location)))
        if owner or group or mode:
            self.dir_attribs(
                location, owner=owner, group=group, mode=mode, recursive=recursive
            )

    # stolen from cuisine
    @server_host_manager
    def dir_attribs(self, location, mode=None, owner=None, group=None, recursive=False):
        """Updates the mode/owner/group for the given remote directory."""
        recursive = recursive and "-R " or ""
        if mode:
            self.run("chmod %s %s %s" % (recursive, mode, shell_safe(location)))
        if owner:
            self.run("chown %s %s %s" % (recursive, owner, shell_safe(location)))
        if group:
            self.run("chgrp %s %s %s" % (recursive, group, shell_safe(location)))

    @server_host_manager
    def prompt(self, text, key=None, default="", validate=None):
        with hide("running"):
            return prompt(text, key=key, default=default, validate=validate)

    @server_host_manager
    def put(
        self,
        local_path=None,
        remote_path=None,
        use_sudo=False,
        mirror_local_mode=False,
        mode=None,
        use_glob=True,
        temp_dir="",
    ):
        """
        Uploads files to remote server
        :param local_path:
        :param remote_path:
        :param use_sudo:
        :param mirror_local_mode:
        :param mode:
        :param use_glob:
        :param temp_dir:
        :return:
        """
        with hide("running"):
            return put(
                local_path=local_path,
                remote_path=remote_path,
                use_sudo=use_sudo,
                mirror_local_mode=mirror_local_mode,
                mode=mode,
                use_glob=use_glob,
                temp_dir=temp_dir,
            )

    def run_as_app_user(self, *args, **kwargs):
        """This should be implemented by apps inheriting this server class."""
        raise NotImplementedError

    @server_host_manager
    def get(self, remote_path, local_path=None, use_sudo=False, temp_dir=""):
        """ Download one or more files from a remote host.
        get(remote_path, local_path=None, use_sudo=False, temp_dir="")
        """
        with hide("running"):
            return get(
                remote_path, local_path=local_path, use_sudo=use_sudo, temp_dir=temp_dir
            )

    @server_host_manager
    def sed(
        self,
        filename,
        before,
        after,
        limit="",
        use_sudo=False,
        backup=".bak",
        flags="",
        shell=False,
    ):
        """ Runs a shell command on the remote server."""
        with hide("running"):
            return sed(
                filename,
                before,
                after,
                limit=limit,
                use_sudo=use_sudo,
                backup=backup,
                flags=flags,
                shell=shell,
            )

    @server_host_manager
    def postfix_conf(self):
        commands = [
            "message_size_limit=20480000",
            "mailbox_size_limit=0",
            "default_destination_concurrency_limit=1",
        ]

        for command in commands:
            self.sudo("postconf -e " + command)
        self.sudo("service postfix restart")

    @server_host_manager
    def postconf(self, command):
        """Send command to postfix."""
        command = command.strip()

        self.sudo("postconf -e " + command)
        self.sudo("service postfix restart")

    @server_host_manager
    def install_postfix(self):
        hostname = run("hostname")
        self.sudo(
            "debconf-set-selections <<< \"postfix postfix/main_mailer_type string 'Internet Site'\" "
        )
        self.sudo(
            "debconf-set-selections <<< 'postfix postfix/mailname string {0}'".format(
                hostname
            )
        )
        self.install_package("postfix")

    @server_host_manager
    def run_as_user(self, command, user=None, show=True):
        """
        Runs a shell command on the remote server as given user.
        """
        user_dir = self._get_home_dir(user=user)[0]
        if show:
            self.print_command(command)
        with hide("running"):
            with self.cd(user_dir):
                return self.sudo(command, user=user)

    @server_host_manager
    def clean_manager(self):
        self.sudo(
            "grep -i security /etc/apt/sources.list | grep -v '\#' > /etc/apt/security.sources.list"
        )
        self.sudo("apt-get -q  update")
        self.sudo(
            "apt-get -q  -o Dir::Etc::SourceList=/etc/apt/security.sources.list upgrade"
        )
        self.sudo("apt-get -q clean")
        self.sudo("apt-get -q autoclean")
        self.sudo("apt-get -q autoremove")
        self.sudo("update-grub")

    @server_host_manager
    def send_ssh(self, user):
        with hide("running", "stdout", "stderr"):
            hostname = self.get_hostname()
            local_user_home = self.local_user_home()
            user_ssh_dir = "{0}/.ssh".format(self._get_home_dir(user=user)[0])

            remote_user_home = self._get_home_dir(user=user)[0]
            remote_user_authorized_keys = "{0}/.ssh/authorized_keys".format(
                remote_user_home
            )
            remote_user_authorized_keys_dir = os.path.dirname(
                remote_user_authorized_keys
            )

            with settings(warn_only=True):
                if not self.exists(remote_user_authorized_keys_dir):
                    self.sudo("mkdir -p {0}".format(remote_user_authorized_keys_dir))
                    self.sudo("chmod 700 {0}".format(remote_user_authorized_keys_dir))

            with settings(warn_only=True):
                if not self.exists(remote_user_authorized_keys):
                    self.sudo("touch {0}".format(remote_user_authorized_keys))
                    self.sudo(
                        "chown {0}:{0} {1}".format(user, remote_user_authorized_keys)
                    )
                    self.sudo("chmod 600 {0}".format(remote_user_authorized_keys))

            with settings(warn_only=True):
                self.local(
                    'yes Y | ssh-keygen -f "{0}/.ssh/known_hosts" -R {1}'.format(
                        local_user_home, hostname
                    )
                )  # remove host if exist

            local_user_ssh_key = "{0}/.ssh/id_rsa.pub".format(local_user_home)
            remote_user_ssh_tmp_key = (
                local_user_ssh_tmp_key
            ) = "/tmp/{0}_id_rsa.pub".format(user)

            self.local(
                "cat {0} > {1}".format(local_user_ssh_key, local_user_ssh_tmp_key)
            )

            self.put(
                local_path=local_user_ssh_tmp_key, remote_path=remote_user_ssh_tmp_key
            )
            self.sudo(
                "cat {0} >> {1}".format(
                    remote_user_ssh_tmp_key, remote_user_authorized_keys
                )
            )
            self.sudo("rm -rf {0}".format(remote_user_ssh_tmp_key))
            self.sudo("chown -R {0}. {1}".format(user, user_ssh_dir))


class BSD(BaseServer):
    def __init__(self, *args, **kwargs):
        super(BSD, self).__init__(*args, **kwargs)
        self.env.shell = "/usr/local/bin/bash -l -c"

    @property
    def distro(self):
        return "BSD"

    def get_package_manager(self):
        return "pkg "

    @server_host_manager
    def update(self, ports=False):
        manager = self.get_package_manager()
        self.sudo("{0} update".format(manager))
        self.sudo("{0} upgrade -y".format(manager))
        self.sudo("{0} autoremove -y".format(manager))

        if ports:
            self.sudo("portsnap auto")

    @server_host_manager
    def uninstall_package(self, package):
        manager = self.get_package_manager()
        command = "{0} delete {1}".format(self.get_package_manager(), package)

        with settings(warn_only=True):
            self.sudo(command)
            self.sudo("{0} autoremove -y".format(manager))

    @server_host_manager
    def is_package_installed(self, package_name):
        pass

    @server_host_manager
    def list_compilers(self):
        pass

    @server_host_manager
    def list_installed_packages(self):
        pass

    # set bash for useres
    def set_shell_to_bash(self, user=None):
        self.sudo(
            'mount -t fdescfs fdesc /dev/fd && echo "fdesc    /dev/fd        fdescfs'
            '        rw    0    0" >> /etc/fstab'
        )

        if user is None:
            self.sudo("chsh -s /usr/local/bin/bash")
        else:
            self.sudo("chsh -s /usr/local/bin/bash {0}".format(user))
            self.sudo(
                "'xterm*Background:    black' >> .Xdefaults && echo 'xterm*Foreground:    white' >> .Xdefaults"
            )
            self.sudo("alias ls='ls -G' >> .bashrc")


class FreeBsd(BSD):
    @property
    def distro(self):
        return "FreeBsd"

    @server_host_manager
    def update(self, ports=False):
        self.sudo("freebsd-update fetch -y")
        self.sudo("freebsd-update install -y")
        super(FreeBsd, self).update(ports=ports)


class Debian(BaseServer):
    @property
    def distro(self):
        return "Debian"

    def get_package_manager(self):
        return "apt-get "

    @server_host_manager
    def list_compilers(self):
        result = self.sudo("dpkg --list | grep gcc")
        return result

    @server_host_manager
    def list_installed_packages(self):
        result = self.sudo("dpkg --list")
        return result


class Ubuntu(Debian):
    @server_host_manager
    def shutdown(self):
        return self.sudo("poweroff")


class RedHat(BaseServer):
    def distro(self):
        return "RedHat"

    def get_package_manager(self):
        return "yum "

    @server_host_manager
    def install_package(self, package):
        super(RedHat, self).install_package(package)
        manager = self.get_package_manager()
        sudo("{0} clear all".format(manager))

    @server_host_manager
    def uninstall_package(self, package_name):
        manager = self.get_package_manager()
        uninstall = "{0} remove --purge {1} -y".format(manager, package_name)
        with settings(warn_only=True):
            return self.sudo(uninstall)

    @server_host_manager
    def list_compilers(self):
        manager = self.get_package_manager()
        self.sudo("{0} list installed '\gcc*'".format(manager))

    @server_host_manager
    def list_installed_package(self):
        manager = self.get_package_manager()
        self.sudo("{0} list installed|less".format(manager))


class CentOS(RedHat):
    pass
