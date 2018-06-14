# coding: utf-8
from __future__ import unicode_literals
import os

from apps.base import BaseApp
from fabobjects.distros import shell_safe

from fabobjects.utils import server_host_manager


class RedisApp(BaseApp):
    """
    A Redis class that defines a set of methods thats used by both redis servers and redis clients.
    """
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


class RedisServer(RedisApp):
    """
    A Redis server class, this class installs and sets up a redis server on a host server.
    """
    def __init__(self, *args, **kwargs):
        """
        :param int service_port = Port to listen for connections, defaults to 6379.
        :param str maxmemory = Max memory redis should use for storage.
        :param str exposed_ip = The ip address redis should to accept connections on, defaults to `None`
        :param str redis_password = Password for your redis server, defaults to `None`
        :param str allowed_ip = A list or string of ip address to accept connections from, defaults to `None`
        :param bool public = Set to `True` if you want redis to accept public connections,
                             by default this is set to `False`
        """
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
        """
        Install and configure redis on a server.
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
        """
        Set memory to be reserved for redis to use for storage
        :param str maxmemory:
        :return:
        """
        afile = shell_safe('/etc/redis/redis.conf')

        if maxmemory is None:
            if self.maxmemory is None:
                self.maxmemory = '256mb'
            maxmemory = self.maxmemory

        self.echo('maxmemory {0}'.format(maxmemory), to=afile,)
        self.echo('maxmemory-policy allkeys-lru', to=afile,)

    @server_host_manager
    def make_public(self, ip="0.0.0.0"):
        """
        Expose redis to public traffic on given ip interface
        :param ip: The ip redis will be listening on.
        :return: None
        """
        afile = shell_safe('/etc/redis/redis.conf')
        self.sed(afile, 'bind 127.0.0.1', 'bind {0}'.format(ip), use_sudo=True)

    @server_host_manager
    def change_port(self, port):
        """
        Change the port which redis is listening on.
        :param int port: The port number redis should listening on
        :return: None
        """
        try:
            port = str(int(port))
        except ValueError as err:
            print("Value error: port must be an int".format(err))
            raise err

        new_port = 'port {0}'.format(port)
        old_port = 'port {0}'.format(self.service_port)

        afile = shell_safe('/etc/redis/redis.conf')
        self.sed(afile, old_port, new_port, use_sudo=True,)
        self.service_port = port

    @server_host_manager
    def set_password(self, pswd=None):
        """
        Set Up password protection for redis server
        :param str pswd: A strong pass word
        :return: None
        """
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
        Enable ssl connection on redis server
        :param str domain: The website domain name
        :param str country_iso:
        :param str state:
        :param str city:
        :param str company_name:
        :return: None
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


class RedisSslClient(RedisApp):
    """
    A Redis ssl client, this class installs and sets up a redis client to talk to a remote redis server over an
    ssl connection.
    """
    def __init__(self, *args, **kwargs):
        """
        Initializes the redis ssl client connection.
        :param str server_ip: The ip address of the remote redis server
        :param str server_cert: Path on your local file system to the server private.pem
        """
        super(RedisSslClient, self).__init__(*args, **kwargs)
        self.server_ip = kwargs.get('server_ip', None)
        self.server_cert = kwargs.get('server_cert', None)
        self.redis_password = kwargs.get('redis_password', None)

    def deploy(self):
        """
        Install and set up a redis client on a host server.
        :return:
        """
        self.install_package("redis-tools stunnel4")
        afile = shell_safe("/etc/default/stunnel4")
        self.sed(afile, "ENABLED=0", "ENABLED=1", use_sudo=True)
        self.put(local_path=self.server_cert, remote_path="/etc/stunnel/")

        combined_cert = shell_safe(os.path.join("/etc/stunnel/",
                                                self.server_cert.split('/')[-1]))
        self.sudo("chmod 640 {0}".format(combined_cert))

        #  Configure stunnel to use our self signed ssl cert
        conf_file = shell_safe("/etc/stunnel/redis-server.conf")

        self.echo("cert = {0}".format(combined_cert),
                  to=conf_file, append=False)
        self.echo("client = yes", to=conf_file)
        self.echo("pid = /var/run/stunnel.pid", to=conf_file)
        self.echo("[redis]", to=conf_file)
        self.echo("accept = 127.0.0.1:6379", to=conf_file)
        self.echo("connect = {0}:6379".format(self.server_ip), to=conf_file)
        self.service_start("stunnel4")
