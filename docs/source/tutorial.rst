.. _ref-tutorial:

============
User Guide
============

Welcome! This tutorial walks you through some common use case and core functionalities of **fab-objects**;
for further details, see the API doc sections.


Installation
=============

Example::


   pip install git+https://github.com/abiolarasheed/fabobjects.git


Initialize new server with ``root`` user
========================================

For the most part when using Fab-Objects you will create a server instance from
one of the built in destros and execute a shell commands by calling a method on
that instance. By default, some cloud providers will give you a root user and
an ip address to the server you have created, for this example we will assume
you have created an ``Ubuntu 16.10 x64`` with Public IP ``199.199.199.99``. Now
let ssh into this box and set it up using ``root@199.199.199.99``.

::

    >>> from os import environ
    >>> from fabobjects.distros import Ubuntu

    >>> workstation_ip = "58.588.588.58"

    >>> ubuntu_server = Ubuntu(hostname="db1", user="root",
    ...                        domain_name="mydomain.com",
    ...                        email="yoursysadmin@mydomain.com",
    ...                        ip='199.199.199.99',
    ...                        password=environ.get("PASSWORD"),
    ...                        user_ip=workstation_ip,
    ...                        )

    >>> # 1st lets create an admin user
    >>> admin_user = "ubuntu"
    >>> ubuntu_server.create_admin_account(admin_user,
    ...                                    environ.get("PASSWORD"))

    >>> # Update and secure the server
    >>> ubuntu_server.harden_server()
    >>> # Root login disabled, and server secured

    >>> # Now login with ubuntu@199.199.199.99 and reboot
    >>> ubuntu_server.rebootall()

    >>> # Install your application
    >>> ubuntu_server.install_package('postgresql-9.6')

On some cloud providers an admin user is provided other than the ``root`` or if you installed the OS
your self there is a chance you have an admin user already. See the table below for *aws* default users
on some OS.


+-------------------------+----------------------------+
| OS/Distro               | Official AMI ssh Username  |
+-------------------------+----------------------------+
| Amazon Linux            |          ec2-user          |
+-------------------------+----------------------------+
| Ubuntu                  |          ubuntu            |
+-------------------------+----------------------------+
| Debian                  |          admin             |
+-------------------------+----------------------------+
| RHEL 6.4 and above      |          ec2-user          |
+-------------------------+----------------------------+


**Initialize new server with admin user**

::

    >>> from os import environ
    >>> from fabobjects.distros import Ubuntu

    >>> admin_user = "ubuntu"
    >>> workstation_ip = "58.588.588.58"

    >>> ubuntu_server = Ubuntu(hostname="db1", user=admin_user,
    ...                        domain_name="mydomain.com",
    ...                        email="yoursysadmin@mydomain.com",
    ...                        ip='199.199.199.99',
    ...                        password=environ.get("PASSWORD"),
    ...                        user_ip=workstation_ip,
    ...                        )

    >>> # Update and secure the server
    >>> ubuntu_server.harden_server()

    >>> # Root login disabled, and server secured
    >>> ubuntu_server.rebootall()

    >>> # Install your application
    >>> ubuntu_server.install_package('postgresql-9.6')


Running custom shell commands
======================================

While fab-objects has a bunch of useful built-in methods, there are times
when you want to run a custom command as the ``superuser`` or as another user or just
as your self(current user). To do this fab-objects exposes 3 methods, ``sudo``,
``run`` and ``run_as_user`` for executing shell commands on your remote system as below.

Using the server from previous samples::

    >>> ubuntu_server.user # just making sure we are the admin user
    'ubuntu'

    >>> ubuntu_server.run("id")  # Run command as current user
    'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),...'

    >>> # Run command as another user(postgres user)
    >>> ubuntu_server.run_as_user("whoami", user='postgres')
    'uid=116(postgres) gid=122(postgres) groups=122(postgres),...'

    >>>  # Run command with sudo
    >>> ubuntu_server.sudo('grep postfix /etc/passwd | cut -d: -f6')
    '/var/spool/postfix'


Managing Firewalls
===================

Firewalls are one of the many layers of security one can use to secure a
server, fab-objects ships with a few firewall method. below are some ways
of setting up and managing your firewalls::

    >>> # Install firewall and allow user_ip in on ssh
    >>> ubuntu_server.install_firewall(user_ip="58.588.588.58")

    >>> # Allow all on http
    >>> ubuntu_server.firewall_allow_form_to(host="all",
    ...                                      proto='tcp',
    ...                                      port=80)

    >>> # Allow more than one rule
    >>> rules = ["ufw allow https", "ufw allow postgres"]
    >>> ubuntu_server.configure_firewall(rules=rules)

    >>> # View current firewall rules
    >>> print(ubuntu_server.view_firewall_rules())
         To          Action      From
         --          ------      ----
    [ 1] 22          LIMIT IN    58.588.588.58
    [ 2] 80/tcp      ALLOW IN    Anywhere
    [ 3] 443/tcp     ALLOW IN    Anywhere
    [ 4] 5432/tcp    ALLOW IN    Anywhere

    >>> # Delete rule 4 (postgres)
    >>> ubuntu_server.delete_firewall_number(4)

    >>> # View status and rules
    >>> print(ubuntu_server.firewall_status())
    Status: active
    Logging: on (low)
    Default: deny (incoming), allow (outgoing), disabled (routed)
    New profiles: skip
         To          Action      From
         --          ------      ----
    [ 1] 22          LIMIT IN    58.588.588.58
    [ 2] 80/tcp      ALLOW IN    Anywhere
    [ 3] 443/tcp     ALLOW IN    Anywhere


File Handling
=======================

Another common task you may often want to perform over SSH are file manipulation,
creation and transfer. Fab-object exposes a few method to cover most use case
and here are a few::


    >>> # Upload/Download files
    >>> ubuntu_server.put("local_tar_file", '/etc/ngix/')
    >>> ubuntu_server.get(local_zip_file, config_path)

    >>> # Zip/Unzip files
    >>> ubuntu_server.zip(ssl_file, file_type="tar")
    >>> ubuntu_server.unzip(zip_file, file_type="zip")

    >>> # Comment/Uncomment/Append/Replace
    >>> ubuntu_server.comment
    >>> ubuntu_server.uncomment
    >>> ubuntu_server.append
    >>> ubuntu_server.sed

    >>> ubuntu_server.exists(path)
    >>> ubuntu_server.comment(filename, regex)
    >>> ubuntu_server.uncomment(filename, regex)
    >>> ubuntu_server.dir_exists(location)
    >>> ubuntu_server.dir_ensure(location, recursive=False)

    >>> # Create/Delete files/folders
    >>> # Create file
    >>> ubuntu_server.make_or_del("/tmp/test.txt", make=True, is_file=True)

    >>> # Delete file
    >>> ubuntu_server.make_or_del("/tmp/test.txt", make=False, is_file=True)

    >>> # Create folders
    >>> ubuntu_server.make_or_del("/tmp/tests/test", make=True)

    >>> # Delete folders
    >>> ubuntu_server.make_or_del("/tmp/test", make=False)


Application Management
=======================

Installing, starting, stopping, reloading and uninstalling are some of the
every day task you'll often want to perform on your remote host, doing it with
fab-objects makes it simple and os independent.
For example, let install and manage ``nginx`` http-server::


    >>> # Check if nginx is installed
    >>> ubuntu_server.is_package_installed('nginx')
    False
    >>> # Install nginx
    >>> ubuntu_server.install_package('nginx')

    >>> # Start Nginx
    >>> ubuntu_server.service_start('nginx')
    >>> # Nginx is ready to start accepting requests

    >>> # You can also Restart(stop/start) nginx
    >>> ubuntu_server.service_restart('nginx')


Now that we have installed nginx and its running just fine,
lets setup our custom domain and ssl::

    >>> # SSL settings
    >>> local_tar_file = "ssl.tgz"
    >>> ssl_file = "/etc/ngix/ssl.tar"

    >>> # Upload ssl cert
    >>> ubuntu_server.put("local_tar_file", '/etc/ngix/')

    >>> # Unzip ssl tar folder
    >>> ubuntu_server.unzip(ssl_file, file_type="tar")

    >>> # Delete the tar file now after untaring it
    >>> ubuntu_server.make_or_del(ssl_file, make=False,
    ...                           use_sudo=True)

    >>> # mydomain settings
    >>> config_path = '/etc/ngix/sites-available/'
    >>> config_file = '/etc/ngix/sites-available/mydomain.com.conf'
    >>> enable_file = '/etc/ngix/sites-enable/mydomain.com.conf'
    >>> local_zip_file = "mydomain.com.conf.zip"

    >>> # Upload config for mydomain.com
    >>> ubuntu_server.put(local_zip_file, config_path)

    >>> # Unzip config zip folder
    >>> zip_file = "{0}.zip".format(config_file)
    >>> ubuntu_server.unzip(zip_file, file_type="zip")

    >>> # Delete the zip file now after unzipping it
    >>> ubuntu_server.make_or_del(zip_file, make=False,
    ...                           use_sudo=True)

    >>> # Enable Nginx
    >>> ubuntu_server.create_symbolic_link(config_file,
    ...                                    enable_file)

    >>> # Check if config file syntax is ok.
    >>> ubuntu_server.sudo("ngix -t")

    >>> # Reload new nginx config
    >>> ubuntu_server.service_reload('nginx')

    >>> # Check nginx status after reload
    >>> ubuntu_server.service_status('nginx')

    >>> # Stop nginx
    >>> ubuntu_server.service_stop('nginx')

    >>> # uninstall nginx maybe you are an apache guy
    >>> ubuntu_server.uninstall_package('nginx')

    >>> # Install apache2
    >>> ubuntu_server.install_package("apache2")


Complete!
=========

This has been a minimal walk through of the fab-objects sever class,
for a more complete list of methods and functionality see the
API docs for more information.
