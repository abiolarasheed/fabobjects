# coding: utf-8
from __future__ import unicode_literals

from apps.base import BaseApp


class PostgresServer(BaseApp):
    """
    Set up Postgres Pry database server.
    """
    name = 'master_setup'
    db_version = '9.3'
    gist_version = '2.1'
    encrypt = 'md5'
    hba_txts = ('local   all    postgres                     ident\n'
                'host    replication replicator  0.0.0.0/0   md5\n'
                'local   all    all                          password\n'
                '# # IPv4 local connections:\n'
                'host    all    all         127.0.0.1/32     %(encrypt)s\n'
                '# # IPv6 local connections:\n'
                'host    all    all         ::1/128          %(encrypt)s\n'
                '# # IPv4 external\n'
                'host    all    all         0.0.0.0/0        %(encrypt)s\n')
    postgres_config = {
        'listen_addresses':  "'*'",
        'wal_level':         "hot_standby",
        'wal_keep_segments': "32",
        'max_wal_senders':   "5",
        'archive_mode':      "on"}

    data_dir_default_base = '/var/pgsql'
    binary_path = None
    version_directory_join = '.'

    def __init__(self,*args,**kwargs):
        super(PostgresServer,self).__init__(*args,**kwargs)
        self.service_name = 'postgresql'
        self.replicator_pass = kwargs.get('replicator_pass', None)
        self.service_port = kwargs.get('service_port', '5432')


class PostgresServerReplica(PostgresServer):
    """ Set up master-slave streaming replication: slave node """
    name = 'slave_setup'
    postgres_config = {
        'listen_addresses': "'*'",
        'wal_level':      "hot_standby",
        'hot_standby':    "on"}

    def __init__(self,*args,**kwargs):
        super(PostgresServerReplica, self).__init__(*args,**kwargs)
        self.service_name = 'postgresql'
        self.master_db = kwargs.get('master_db', None)
        self.service_port = kwargs.get('service_port', '5432')


class PGBouncer(BaseApp):
    """
    Set up PGBouncer on a database server
    """
    name = 'setup_pgbouncer'
    config_dir = '/etc/pgbouncer'
    config = {
        '*':              'host=127.0.0.1',
        'logfile':        '/var/log/pgbouncer/pgbouncer.log',
        'pidfile':        None,
        'listen_addr':    '*',
        'listen_port':    '6432',
        'unix_socket_dir': '/tmp',
        'auth_type':      'md5',
        'auth_file':      '%s/userlist.txt' % config_dir,
        'pool_mode':      'session',
        'admin_users':    'postgres',
        'stats_users':    'postgres',
        }

    def __init__(self, *args, **kwargs):
        super(PGBouncer, self).__init__(*args, **kwargs)
        self.config['db_host'] = kwargs.get('db_host', '127.0.0.1')
