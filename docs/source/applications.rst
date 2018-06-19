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


Managing PostgreSql
======================


Bring it all together
=======================


Creating your own Application!
==============================

This has been a minimal walk through of the fab-objects API,
for a more complete list of methods see the API docs for more information.
