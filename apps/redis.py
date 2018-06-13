# coding: utf-8
from __future__ import unicode_literals
import os

from apps.base import BaseApp
from fabobjects.distros import shell_safe

from fabobjects.utils import server_host_manager


class RedisServer(BaseApp):
    def __init__(self, *args, **kwargs):
        super(RedisServer, self).__init__(*args, **kwargs)
        self.service_name = 'redis-server'
        self.service_port = kwargs.get('service_port', '6379')
        self.maxmemory = kwargs.get('maxmemory', None)
        self.exposed_ip = kwargs.get('exposed_ip', None)
        self.redis_password = kwargs.get('redis_password', None)
        self.allowed_ip = kwargs.get("allowed_ip", None)
        self.public = kwargs.get("public", False)

    def status(self):
        """
        A method for restarting the application.
        :return: None
        """
        return self.service_status(self.service_name)

    def reload(self):
        """
        A method for reload the redis.
        :return: None
        """
        return self.service('{0} force-reload'.format(self.service_name))

    def start(self):
        """
        A method for starting redis.
        :return: None
        """
        return self.service_start(self.service_name)

    def stop(self):
        """
        A method for stopping redis.
        :return: None
        """
        return self.service_stop(self.service_name)

    def restart(self):
        """
        A method for restarting redis.
        :return: None
        """
        return self.service_restart(self.service_name)

    @server_host_manager
    def deploy(self):
        """ Deploy Redis to a server
        :return: None
        """
        self.install_package('redis-server')

        if self.redis_password is not None:
            self.set_password(pswd=self.redis_password)

        if self.maxmemory is not None:
            self.set_memory_limit(maxmemory=self.maxmemory)

        if self.public:
            self.make_public(self)
            self.firewall_conf(self.allowed_ip)

    @server_host_manager
    def set_memory_limit(self, maxmemory=None):
        afile = shell_safe('/etc/redis/redis.conf')

        if maxmemory is None:
            if self.maxmemory is None:
                self.maxmemory = '256mb'

            maxmemory = self.maxmemory

        self.echo('maxmemory {0}'.format(maxmemory), to=afile,)
        self.echo('maxmemory-policy allkeys-lru', to=afile,)

    @server_host_manager
    def make_public(self):
        afile = shell_safe('/etc/redis/redis.conf')
        self.sed(afile, 'bind 127.0.0.1',
                 'bind 0.0.0.0', use_sudo=True)

    @server_host_manager
    def change_port(self, port):
        new_port = 'port {0}'.format(port)
        old_port = 'port {0}'.format(self.service_port)

        afile = shell_safe('/etc/redis/redis.conf')
        self.sed(afile, old_port, new_port, use_sudo=True,)
        self.service_port = port

    @server_host_manager
    def set_password(self, pswd=None):
        afile = shell_safe('/etc/redis/redis.conf')

        if pswd is None:
            raise RuntimeError('You did not enter password')

        self.sed(afile, '# requirepass foobared',
                 'requirepass {0}'.format(pswd), use_sudo=True)

        if self.redis_password != pswd:
            self.redis_password = pswd

    @server_host_manager
    def firewall_conf(self):
        """
        Expose ip or list of ips that can no
        :return:None
        """
        if self.allowed_ip is None:
            return

        if type(self.allowed_ip) != list:
            self.allowed_ip = [self.allowed_ip]

        [self.firewall_allow_form_to(host=host,
                                     to=self.exposed_ip,
                                     proto='tcp',
                                     port=self.service_port) for host in self.allowed_ip]

    def enable_ssl(self, domain=None, country_iso=None,
                   state=None, city=None, company_name=None):
        """
        enable ssl connection to redis server
        :param domain:
        :param country_iso:
        :param state:
        :param city:
        :param company_name:
        :return:
        """
        # Install and configure stunnel to start on boot
        self.install_package("stunnel4")
        afile = shell_safe("/etc/default/stunnel4")
        self.sed(afile, "ENABLED=0", "ENABLED=1", use_sudo=True)

        # Create self signed ssl cert
        conf_file = shell_safe("/etc/stunnel/redis-server.conf")
        ssl_dir = shell_safe("/etc/stunnel/")
        combined_cert = os.path.join(ssl_dir, os.path.join("certs", "private.pem"))

        self.generate_self_signed_ssl(domain=domain, cert_dir=ssl_dir,
                                      country_iso=country_iso, state=state,
                                      city=city, company_name=company_name)

        ssl_dir = os.path.join(ssl_dir, "certs")
        self.sudo("cat {0}/{1}.key {0}/{1}.crt > {2}".format(ssl_dir, domain, combined_cert))
        self.sudo("chmod 640 {0}".format(combined_cert))

        #  Configure stunnel to use our self signed ssl cert
        self.echo("cert = {0}".format(combined_cert), to=conf_file, append=False)
        self.echo("pid = /var/run/stunnel.pid", to=conf_file)
        self.echo("[redis]", to=conf_file)
        self.echo("accept = {0}:6379".format(self.exposed_ip), to=conf_file)
        self.echo("connect = 127.0.0.1:6379", to=conf_file)

        # Ensure redis is listening on localhost since stunnel is listen on the public ip
        afile = shell_safe('/etc/redis/redis.conf')
        self.sed(afile, 'bind 0.0.0.0', 'bind 127.0.0.1', use_sudo=True)

        self.service_restart("redis")
        self.service_start("stunnel4")

    def redis_cli(self, command):
        """
        Run redis command
        :param str command: The command you want to pass to redis
        :return:
        """
        if self.redis_password is not None:
            command = "redis-cli -a {0} {1}".\
                format(self.redis_password, command)

        else:
            command = "redis-cli {0}".format(command)

        return self.run(command)
