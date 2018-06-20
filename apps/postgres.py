# coding: utf-8
from __future__ import unicode_literals

import getpass
import os
import sys
from apps.base import BaseApp
from fabobjects.utils import server_host_manager, random_password


PG_VERSION = "9.6"
GIST_VERSION = "2.3"
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
        name = 'master_setup'
        self.service_name = 'postgresql'
        self.replicator_pass = kwargs.get('replicator_pass', None)
        self.service_port = kwargs.get('service_port', '5432')
        self.db_version = kwargs.get("", PG_VERSION)
        self.gist_version = kwargs.get("", GIST_VERSION)
        self.encrypt = kwargs.get("", 'md5')
        self.hba_text = kwargs.get("", HBA_TEXT)
        self.postgres_config = kwargs.get("", POSTGRES_CONFIG)
        self.data_dir_default_base = kwargs.get("", '/var/pgsql')
        self.binary_path = kwargs.get("", None)
        self.version_directory_join = kwargs.get("", '.')

    @server_host_manager
    def __get_db_version(self, db_version=PG_VERSION):
        if not db_version:
            db_version = self.db_version
        return self.version_directory_join.join(db_version.split('.')[:2])

    @server_host_manager
    def __install(self, enable_postgis=False, db_version=PG_VERSION,
                  gist_version=GIST_VERSION):
        """

        :param enable_postgis:
        :param db_version:
        :param gist_version:
        :return:
        """
        db_version = db_version or self.db_version
        gist_version = gist_version or self.gist_version
        self.install_package("postgresql-{0}-postgis-{1}".format(db_version, gist_version))

        if enable_postgis:
            self.enable_postgis()

    def install(self):
        return self.__install()

    @server_host_manager
    def turn_pg(self):
        '''usefull info found in link below
        http://brittoc.wordpress.com/2012/11/09/tune-your-postgres-with-pgtune/
        '''
        config_file = '/etc/postgresql/{0}/main/postgresql.conf'.format(self.db_version)
        out_file = 'postgresql.conf'
        with self.cd('/tmp'):
            self.run('wget http://pgfoundry.org/frs/download.php/2449/pgtune-0.9.3.tar.gz')
            self.run('tar -zxvf pgtune-0.9.3.tar.gz')
            with self.cd('pgtune-0.9.3'):
                self.sudo('python pgtune -i {0} -o {1}'.format(config_file, out_file))
                self.sudo('cp {0} {1}.bak'.format(config_file, config_file))
                self.sudo('mv %s %s'%(out_file, config_file))
                self.service_reload('postgresql')
            self.sudo('rm -rf pgtun*')

    @server_host_manager
    def psql(self, sql, show=True, use_table=None):
        """ Runs SQL against the project's database. """
        psql = 'psql {0} -c'.format(use_table) if use_table else 'psql -c'

        out = self.sudo('{0} \'{1}\' '.format(psql, sql), user='postgres')
        if show:
            self.print_command(sql)
        return out

    @server_host_manager
    def create_db(self, dbname=None):
        command = "CREATE DATABASE {}".format(dbname)
        self.psql(command)

    @server_host_manager
    def create_user(self, user=None, passwd=None):
        with self.settings(warn_only=True):
            command = "CREATE USER {0}".format(user)
            self.psql(command)

            if passwd:
                with self.hide('running', 'stdout', 'stderr'):
                    command = 'ALTER USER {0} WITH ENCRYPTED ''PASSWORD \"\'{1}\'\"'.format(user, passwd)
                    self.psql(command)

    @server_host_manager
    def grant_permision(self, permission_type='All', table_name=None, role_name=None):
        opts = dict(permission_type=permission_type, table_name=table_name, role_name=role_name)
        command = "GRANT %(permission_type)s ON DATABASE %(table_name)s TO %(role_name)s".format(**opts)
        self.psql(command)

    @server_host_manager
    def create_postgis_db(self, db):
        self.create_db(dbname=db)
        self.psql('CREATE EXTENSION postgis;', use_table=db)
        self.psql('CREATE EXTENSION postgis_topology;', use_table=db)

    @server_host_manager
    def enable_postgis(self):
        with self.settings(warn_only=True):
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
            origin = "#%s =" %key
            new = "%s = %s" %(key, value)
            self.sudo('sed -i "/{0}/ c\{1}" {2}'.format(origin, new, filename))

    @server_host_manager
    def __setup_hba_config(self, config_dir, encrypt=None):
        """ enable postgres access without password from localhost """
        if not encrypt:
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
            print ('Could not find file {0}. Please make sure postgresql was '
                   'installed and data dir was created correctly.'.format(postgres_conf))
            sys.exit(1)

    @server_host_manager
    def __setup_archive_dir(self, data_dir):
        ''' see link for more detail -->
            http://www.postgresql.org/docs/9.3/interactive/\
            continuous-archiving.html
        '''
        archive_dir = os.path.join(data_dir, 'wal_archive')
        self.sudo("mkdir -p {0}".format(archive_dir))
        self.sudo("chown postgres:postgres {0}".format(archive_dir))
        return archive_dir

    @server_host_manager
    def __get_home_dir(self):
        return super(PostgresServer, self)._get_home_dir(user='postgres')[0]

    @server_host_manager
    def __setup_ssh_key(self, pswd):
        ssh_dir = os.path.join(self.__get_home_dir(), '.ssh')
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
    def __create_replicator(self, replicator_pass=None):#db_version, section):
        if replicator_pass is None and self.replicator_pass is None:
            self.replicator_pass = random_password(12)
            command = 'CREATE USER replicator REPLICATION LOGIN ENCRYPTED PASSWORD \"\'{0}\'\"'.format(replicator_pass)
            self.psql(command)

            history_file = os.path.join(self.__get_home_dir(), '.psql_history')

            if self.exists(history_file):
                self.sudo('rm {0}'.format(history_file))
            return replicator_pass
        else:
            print("user replicator already exists, skipping creating user.")
            return None

    @server_host_manager
    def _run(self, db_version=PG_VERSION, encrypt=None, save_config=False,
             enable_postgis=False, master=False, dbname=None, user=None,
             passwd=None, **kwargs):
        """

        :param db_version:
        :param encrypt:
        :param save_config:
        :param enable_postgis:
        :param master:
        :param dbname:
        :param user:
        :param passwd:
        :param kwargs:
        :return:
        """
        self.__install(enable_postgis=enable_postgis, db_version=db_version,
                       gist_version=kwargs.get('gist_version'))

        data_dir = self.__get_data_dir(db_version)
        config_dir = self.__get_config_dir(db_version,)
        config = dict(self.postgres_config)
        config['archive_command'] = ("'cp %s %s/wal_archive/%s'" %('%p', data_dir, '%f'))
        self.__setup_hba_config(config_dir, encrypt)
        self.__setup_postgres_config(config_dir, config)
        self.__setup_archive_dir(data_dir)
        self.service_restart()

        if enable_postgis:
            self.create_postgis_db(dbname)
        else:
            self.create_db(dbname = dbname)
        self.create_user(user=user, passwd=passwd)
        self.grant_permision(permission_type='All',
                             table_name=dbname, role_name=user)
        if master:
            self.__create_replicator()

        if save_config:
           self.env.config_object.save(self.env.conf_filename)

    @server_host_manager
    def db_pass(self):
        """ Prompts for the database password if unknown. """
        if not self.env.db_pass:
           self.env.db_pass = getpass("Enter the database password: ")
        return self.env.db_pass

    @server_host_manager
    def postgres_run(self, command):
        """ Runs the given command as the postgres user. """
        show = not command.startswith("psql")
        return self.run("sudo -u root sudo -u postgres %s" % command, show=show)

    @server_host_manager
    def clone_db(self, remotehost, remotehost_user, remote_db, local_host_user):
        command = 'pg_dump -C -h {0} -U \
        {1} -d {2} | psql -h {4} -d {2} -U abi'.\
        format(remotehost,remotehost_user,remote_db,local_host_user, self.ip)
        self.sudo(command,user='postgres')

    @server_host_manager
    def backup(self, proj_name, filename):
        """ Backs up the database. """
        return self.postgres_run("pg_dump -Fc %s > %s" % (proj_name, filename))

    @server_host_manager
    def restore(self, filename):
        """ Restores the database. """
        return self.postgres_run("pg_restore -c -d %s %s" % (self.env.proj_name, filename))

    @server_host_manager
    def set_daily_backup(self, password):
        # configure daily dumps of all databases
        self.dir_ensure('/var/backups/postgresql', recursive=True)
        self.sudo("echo 'localhost:*:*:postgres:%s' > /root/.pgpass" % password)
        self.sudo('chmod 600 /root/.pgpass')
        self.sudo("echo '0 7 * * * pg_dumpall --username postgres --file "
                  "/var/backups/postgresql/postgresql_$(date +%%Y-%%m-%%d).dump' > "
                  "/etc/cron.d/pg_dump")


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
