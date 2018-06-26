# coding: utf-8
from __future__ import unicode_literals

import getpass
import os
import sys

from fabric.api import hide
from fabric.api import settings

from apps.base import BaseApp
from fabobjects.utils import server_host_manager, random_password


PG_VERSION = "9.5"
GIS_VERSION = "2.2"
HBA_TEXT = ('local   all    postgres                     ident\n'
            'host    replication replicator  0.0.0.0/0   md5\n'
            'local   all    all                          password\n'
            '# # IPv4 local connections:\n'
            'host    all    all         127.0.0.1/32     %(encrypt)s\n'
            '# # IPv6 local connections:\n'
            'host    all    all         ::1/128          %(encrypt)s\n'
            '# # IPv4 external\n'
            'host    all    all         0.0.0.0/0        %(encrypt)s\n'
            )
POSTGRES_CONFIG = {
    'listen_addresses': "'*'",
    'wal_level': "hot_standby",
    'wal_keep_segments': "32",
    'max_wal_senders': "5",
    'archive_mode': "on"
}


class PostgresServer(BaseApp):
    """
    Set up Postgres Pry database server.
    """
    def __init__(self, *args, **kwargs):
        super(PostgresServer, self).__init__(*args, **kwargs)
        self.name = 'master_setup'
        self.service_name = 'postgresql'
        self.db_pass = kwargs.get("db_pass", None) or self.get_db_pass()
        self.db_name = kwargs.get("db_name", None)
        self.db_user = kwargs.get("db_user", None)
        self.replicator_pass = kwargs.get('replicator_pass', None)
        self.service_port = kwargs.get('service_port', '5432')
        self.db_version = kwargs.get("db_version", PG_VERSION)
        self.gis_version = kwargs.get("gis_version", GIS_VERSION)
        self.encrypt = kwargs.get("encrypt", 'md5')
        self.hba_text = kwargs.get("hba_text", HBA_TEXT)
        self.postgres_config = kwargs.get("postgres_config", POSTGRES_CONFIG)
        self.data_dir_default_base = kwargs.get("data_dir_default_base", '/var/pgsql')
        self.binary_path = kwargs.get("binary_path", None)
        self.version_directory_join = kwargs.get("version_directory_join", '.')

    @server_host_manager
    def deploy(self, db_version=PG_VERSION, encrypt='md5', gis_version=GIS_VERSION,
               enable_postgis=False, master=False, db_name=None, db_user=None,
               passwd=None):
        """
        Install and configure postgres.
        :param db_version: Postgres Version to install
        :param string encrypt: Set encryption type for user password.
        :param string gis_version: PostGis Version to install
        :param bool enable_postgis: Configure PostGis if true
        :param bool master: Set True if it's a master db of a cluster
        :param string db_name: Name of Data base you are creating
        :param db_user: Name of user for the db you are creating
        :param string passwd: Password for the user you are creating
        :return:
        """
        db_version = db_version or self.db_version
        gis_version = gis_version or self.gis_version

        db_name = db_name or self.db_name
        db_user = db_user or self.db_user
        passwd = passwd or self.db_pass

        if all([db_version, gis_version]):
            package = "postgresql-{0}-postgis-{1}".format(db_version, gis_version)

        else:
            package = "postgresql-{0}".format(db_version)

        try:
            self.install_package(package)
            if enable_postgis:
                try:
                    self.create_postgis_db(db=db_name)
                except:
                    pass

            self.create_db(dbname=db_name)
            self.create_db_user(user=db_user, passwd=passwd)
            self.grant_permission(permission_type='All',
                                  db=db_name, role_name=db_user)

            data_dir = self.__get_data_dir(db_version)
            config_dir = self.__get_config_dir(db_version, )
            config = dict(self.postgres_config)
            config['archive_command'] = "'cp {0} {1}/wal_archive/{2}'".format('%p', data_dir, '%f')
            self.__setup_hba_config(config_dir, encrypt)
            self.__setup_postgres_config(config_dir, config)
            self.__setup_archive_dir(data_dir)
            self.service_restart()

            if master:
                self.__create_replicator()
        except:
            return

    @server_host_manager
    def __get_db_version(self, db_version=None):
        if not db_version or db_version is None:
            db_version = self.db_version
        return self.version_directory_join.join(db_version.split('.')[:2])

    @server_host_manager
    def turn_pg(self):
        self.install_package("pgtune")
        if self.is_package_installed("pgtune"):
            config_file = '/etc/postgresql/{0}/main/postgresql.conf'.format(self.db_version)
            out_file = 'postgresql.conf'

            self.sudo('python pgtune -i {0} -o {1}'.format(config_file, out_file))
            self.sudo('cp {0} {1}.bak'.format(config_file, config_file))
            self.sudo('mv {0} {1}'.format(out_file, config_file))
            self.service_reload('postgresql')
        else:
            print("E: Unable to locate package pgtune")

    @server_host_manager
    def psql(self, sql, show=True, use_table=None):
        """ Runs SQL against the project's database. """
        if use_table and use_table is not None:
            psql_ = 'psql {0} -c'.format(use_table)
        else:
            psql_ = 'psql -c'

        out = self.sudo('{0} \'{1}\' '.format(psql_, sql), user='postgres')

        if show:
            self.print_command(sql)
        return out

    @server_host_manager
    def create_db(self, dbname=None):
        command = "CREATE DATABASE {0}".format(dbname)
        self.psql(command)

    @server_host_manager
    def create_db_user(self, user=None, passwd=None):
        with settings(warn_only=True):
            command = "CREATE USER {0}".format(user)
            self.psql(command)

            if passwd:
                with hide('running', 'stdout', 'stderr'):
                    command = 'ALTER USER {0} WITH ENCRYPTED ''PASSWORD \"\'{1}\'\";'.format(user, passwd)
                    self.psql(command)

    @server_host_manager
    def grant_permission(self, permission_type='All', db=None, role_name=None):
        opts = dict(permission_type=permission_type, db=db, role_name=role_name)
        command = "GRANT {permission_type} ON DATABASE {db} TO {role_name}".format(**opts)
        self.psql(command)

    @server_host_manager
    def create_postgis_db(self, db=None):
        with settings(warn_only=True):
            self.psql("ALTER EXTENSION postgis UPDATE;")
            if db is not None:
                self.create_db(dbname=db)
                self.psql('CREATE EXTENSION postgis;', use_table=db)
                self.psql('CREATE EXTENSION postgis_topology;', use_table=db)
            else:
                self.psql("CREATE EXTENSION postgis;")
                self.psql("CREATE EXTENSION postgis_topology;")

    def __get_data_dir(self, db_version):
        data_dir = '/var/lib/postgresql/{0}/main'.format(db_version)
        return data_dir

    @property
    def data_dir(self):
        return self.__get_data_dir(self.__get_db_version())

    def __get_config_dir(self, db_version):
        data_dir = '/etc/postgresql/{0}/main'.format(db_version)
        return data_dir

    @server_host_manager
    def __setup_parameter(self, filename, **kwargs):
        for key, value in kwargs.items():
            origin = "#{0} =".format(key)
            new = "{0} = {1}".format(key, value)
            self.sudo('sed -i "/{0}/ c\{1}" {2}'.format(origin, new, filename))

    @server_host_manager
    def __setup_hba_config(self, config_dir, encrypt=None):
        """ enable postgres access without password from localhost """
        if not encrypt or encrypt is not None:
            encrypt = self.encrypt

        hba_conf = os.path.join(config_dir, 'pg_hba.conf')
        kwargs = {'encrypt': encrypt}
        hba_text = self.hba_text % kwargs

        if self.exists(hba_conf, use_sudo=True):
            self.sudo("echo '{0}' > {1}".format(hba_text, hba_conf))
        else:
            print('Could not find file {0}. Please make sure postgresql was '
                  'installed and data dir was created correctly.'.format(hba_conf))
            sys.exit(1)

    @server_host_manager
    def __setup_postgres_config(self, config_dir, config):
        postgres_conf = os.path.join(config_dir, 'postgresql.conf')
        if self.exists(postgres_conf, use_sudo=True):
            self.__setup_parameter(postgres_conf, **config)
        else:
            print('Could not find file {0}. Please make sure postgresql was '
                   'installed and data dir was created correctly.'.format(postgres_conf))
            sys.exit(1)

    @server_host_manager
    def __setup_archive_dir(self, data_dir):
        """
        Set up dir for continuous archiving.
        :param data_dir:
        :return:
        """
        archive_dir = os.path.join(data_dir, 'wal_archive')
        self.sudo("mkdir -p {0}".format(archive_dir))
        self.sudo("chown postgres:postgres {0}".format(archive_dir))
        return archive_dir

    @server_host_manager
    def get_home_dir(self):
        return self._get_home_dir(user='postgres')[0]

    @server_host_manager
    def __setup_ssh_key(self, pswd):
        ssh_dir = os.path.join(self.get_home_dir(), '.ssh')
        self.sudo('mkdir -p {0}'.format(ssh_dir))
        rsa = os.path.join(ssh_dir, 'id_rsa')

        if self.exists(rsa, use_sudo=True):
            print("rsa key exists, skipping creating")

        else:
            with self.cd(ssh_dir):
                command = "ssh-keygen -t rsa -b 4096 -f {0} -N {1}".format(rsa, pswd)
                self.sudo('chown -R postgres:postgres {0}'.format(ssh_dir))
                self.sudo('chmod -R og-rwx {0}'.format(ssh_dir))
                self.sudo(command, user='postgres')

    @server_host_manager
    def add_user_2_db(self, db_user, db_pass):
        command = "CREATE USER {0} WITH NOCREATEDB NOCREATEUSER ENCRYPTED PASSWORD '{1}' ".format(db_user, db_pass)
        self.psql(command)

    @server_host_manager
    def __create_replicator(self, replicator_pass=None):
        if replicator_pass is None and self.replicator_pass is None:
            self.replicator_pass = replicator_pass = random_password(12)
            command = 'CREATE USER replicator REPLICATION LOGIN ENCRYPTED PASSWORD \"\'{0}\'\"'.format(replicator_pass)

            self.psql(command)

            history_file = os.path.join(self.get_home_dir(), '.psql_history')

            if self.exists(history_file):
                self.sudo('rm {0}'.format(history_file))
            return replicator_pass
        else:
            print("user replicator already exists, skipping creating user.")
            return None

    @server_host_manager
    def get_db_pass(self):
        """ Prompts for the database password if unknown. """
        if not self.db_pass or self.db_pass is None:
            self.db_pass = getpass("Enter the database password: ")
        return self.db_pass

    @server_host_manager
    def postgres_run(self, command):
        """ Runs the given command as the postgres user. """
        return self.run_as_user(command, user="postgres")

    @server_host_manager
    def clone_db(self, remotehost, remotehost_user, remote_db, local_host_user):
        command = 'pg_dump -C -h {0} -U {1} -d {2} | psql -h {4} -d {2} -U {3}'\
            .format(remotehost, remotehost_user, remote_db, local_host_user, self.ip)
        self.sudo(command, user='postgres')

    @server_host_manager
    def backup(self, project_name, filename):
        """ Backs up the database. """
        return self.postgres_run("pg_dump -Fc {0} > {1}".format(project_name, filename))

    @server_host_manager
    def restore(self, project_name, filename):
        """ Restores the database. """
        return self.postgres_run("pg_restore -c -d {0} {1}".format(project_name, filename))

    @server_host_manager
    def set_daily_backup(self, password):
        # configure daily dumps of all databases
        self.sudo('mkdir -p /var/backups/postgresql')
        self.echo("localhost:*:*:postgres:{0}".format(password),
                  to="/root/.pgpass", use_sudo=True, append=True)
        self.sudo('chmod 600 /root/.pgpass')
        self.echo("0 7 * * * pg_dumpall --username postgres --file /var/backups/postgresql/postgresql_$"
                  "(date +%%Y-%%m-%%d).dump",
                  to="/etc/cron.d/pg_dump")


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
