.. _ref-applications:

=====================
Built-in Applications
=====================

Installing and configuring applications are sometimes complex and hard, but they also require the
developer to login via SSH to do so manual labor. The application class helps limit this and often
just require the developer to call a class method to perform the remote task. Application classes
are simple and flexible to use or extend.


Managing Redis
===============
For this example we will install and configure redis on our server::


    >>> from fabobjects import RedisServer
    >>> from os import environ

    >>> ubuntu_server = Ubuntu(**config_dict)

    >>> # Redis configuration
    >>> redis_config = {'maxmemory':'256mb', 'public':False}

    >>> # Create redis instance
    >>> redis = ubuntu_server.create_app(RedisServer, redis_config)

    >>> # Install and configure redis
    >>> redis.deploy()

    >>> # To send commands to redis server
    >>> redis.redis_cli("PING")
    "PONG"


.. note::

    You have to pass the application class and the application config to the server
    instance ``create_app`` method to instantiate an application. This gives the
    application all the server settings, along with all the server methods too.

    Example: **redis = ubuntu_server.create_app(RedisServer, redis_config)**


The sample above is simple and often perfect for situations where the application
storing and retrieving data from and to the redis-server lives on the same host as the redis-server.
But when your user base increases you will want to place your redis-server on a different host,
and have your applications connect to it **securely** over ssl with password authentication.
In our next example we will set up a redis-server that can accepts ssl connection with ssl
cert and password authentication::


    >>> from fabobjects import Debian, Ubuntu
    >>> from myapp.conf import config_dict, app_config_dict

    >>> # Create our servers
    >>> cache_server = Ubuntu(**config_dict)  # private '10.10.10.1'
    >>> flask_app_server = Debian(**app_config_dict) # private '10.10.10.2'


The code above shows our two servers we created, one will hold our flask app
, the other will hold our redis-server. Next we configure the redis-server
to listen and accept connection on its internal ip('10.10.10.1') over ssl
but with password authentication.::


    >>> # Redis configuration
    >>> redis_config = {"maxmemory": "256mb",
    ...                 "exposed_ip": "10.10.10.1",
    ...                 "redis_password": environ.get("REDIS_PASSWORD"),
    ...                 "allowed_ip": "10.10.10.2",
    ...                 "public": False}

    >>> # instantiate a redis-server
    >>> redis = cache_server.create_app(RedisServer, redis_config)

    >>> # configure and install redis-server
    >>> redis.deploy()

    >>> # Redis ssl configuration used to generate self signed ssl cert
    >>> ssl_conf = {"domain": "example.com", "country_iso": "US",}
    ...             "state": "California", "city": "San Francisco",
    ...             "company_name":"Example Inc")

    >>> # Configure ssl for redis
    >>> redis.enable_ssl(**ssl_conf)

    >>> # To send commands to redis server
    >>> redis.redis_cli("PING")
    "PONG"


Next we setup our redis client on our other server, so it can communicate
with the redis-server over ssl connecting using our internal next work ip addresses
for added security by not totaly exposing redis to public internet. Then we will
open our firewalls to allow connection from the client to the server::


    >>> # Download the private.pm from the redis-server to our local workstation
    >>> # The private.pem is downloaded to our /tmp/private.pem
    >>> # This will be used to encrypt communication by both servers

    >>> cache_server.get("/etc/redis/ssl/certs/private.pem",
    ...                   local_path="/tmp/", use_sudo=True)

    >>> redis_client_config = {"redis_password": environ.get("REDIS_PASSWORD"),
    ...                        "server_ip": "10.10.10.1",
    ...                        "server_cert": "/tmp/private.pem"
    ...                        }

    >>> redis_client = flask_app_server.create_app(RedisSslClient, redis_client_config)

    >>> # Upload the private.pem to our flask server now then set it all up
    >>> redis_client.deploy()

    >>> # set key from client
    >>> redis_client.redis_cli("SET greetings 'Hello'")
    "OK"

    >>> # test redis server if key exist
    >>> redis.redis_cli("GET greetings")
    "Hello"


Managing PostgreSQL
======================
PostgreSQL, is an object-relational database management system often
used in many python applications. Configuring and managing postgres
is relatively simple with fab-objects::

    >>> from fabobjects import PostgresServer

    >>> # Note if gis_version is not set to None PostGis will we installed along with Postgres
    >>> db_config = {"db_pass":"password1", "db_name":"testdb1", "db_user":"test_db_user"
    ...              "gis_version": None}
    >>>
    >>> postgres = ubuntu_server.create_app(PostgresServer, db_config)

    >>> # install and configure postgres
    >>> postgres.deploy()
    >>> # Please note that the db_user will be granted ``All`` permissions on db


.. note::

    Please note that postgres 9.5 and postgis 2.2 are installed by default,
    and you can change this passing the version you want to the constructor.

    Example: db_config = {..., 'gis_version': '2.3', 'db_version':'9.6'}



Now that we have postgres up and running lets run some commands and see how things work::

    >>> db_name = "testdb2"
    >>> db_user = "test_db_user2"
    >>> passwd = "password2"

    >>> # Create a database
    >>> postgres.create_db(dbname=db_name)

    >>> # Create a new db user
    >>> postgres.create_db_user(user=db_user, passwd=passwd)

    >>> # Grant user permission
    >>> postgres.grant_permission(permission_type='SELECT', db=db_name,
    ...                           role_name=db_user)

    >>> # Run SQL commands
    >>> postgres.psql("SELECT * FROM books WHERE book_id >= 100 ORDER BY book_id ASC;")

    >>> # Run Shell Command with user postgres
    >>> postgres.postgres_run('touch /tmp/postgres.txt')

    >>> # Clone / backup / restore settings
    >>> remote_host = "155.155.155.55"
    >>> remote_host_user = "db_user"
    >>> remote_db_name = "test1"
    >>> local_host_user = "am_local"
    >>> backup_filename = "backup_filename.sql"

    >>> # Clone a remote db
    >>> postgres.clone_db(remote_host, remote_host_user, remote_db_name, local_host_user)

    >>> # Backup a db
    >>> postgres.backup(remote_db_name, backup_filename)

    >>> # Restore a db
    >>> postgres.restore(remote_db_name, filename)

    >>> # Set Up daily backups
    >>> password = "somepasswords"
    >>> postgres.set_daily_backup(password)


**Installing PostGIS and PostgreSQL**

PostGis is installed by default, except if you turn it off when initializing your app by
setting ``gis_version = None``::


    >>> from fabobjects import Ubuntu, PostgresServer
    >>> from myapp import server_config

    >>> ubuntu_server = Ubuntu(**server_config)

    >>> db_config = {"db_pass":"password1", "db_name":"testdb1", "db_user":"test_db_user"}

    >>> # By default postgres-9.5 gets installed with postgis-2.2
    >>> postgres_n_gis = ubuntu_server.create_app(PostgresServer, db_config)

    >>> # To install a specific gis version
    >>> db_config = {"db_pass":"password1", "db_name":"testdb1", "db_user":"test_db_user",
    ...              "db_version": "9.6", "gis_version": "2.3"}

    >>> # This will install postgres-9.6 gets installed with postgis-2.3
    >>> postgres_n_gis = ubuntu_server.create_app(PostgresServer, db_config)


Now postGIS is installed along with postgreSQL and enabled. You can
begin to create your geographic objects and run location queries in SQL.


**Postgresql Replication**::


    >>> from fabobjects import PostgresServer, PostgresServerReplica

    >>> # server config
    >>> pry_db_config = {}
    >>> replica_config = {}



Managing Nginx
=================


Managing Git Remote Server
===========================


Managing Python Applications
=============================


Bring it all together
=======================


Creating your own Application!
==============================

This has been a minimal walk through of the fab-objects API,
for a more complete list of methods see the API docs for more information.
