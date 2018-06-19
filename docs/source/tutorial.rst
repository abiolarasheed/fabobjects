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
    >>> from fabobjects import Ubuntu

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
    >>> from fabobjects import Ubuntu

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
    >>> ubuntu_server.run_as_user("id", user='postgres')
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


    >>> ubuntu_server.put  # Upload files
    >>> ubuntu_server.get  # Download files

    >>> # Compress/Uncompress files
    >>> ubuntu_server.compress    # Compress files
    >>> ubuntu_server.uncompress  # Uncompress files

    >>> # Comment/Uncomment/Append/Replace
    >>> ubuntu_server.comment
    >>> ubuntu_server.uncomment
    >>> ubuntu_server.append
    >>> ubuntu_server.sed

    >>> # Checks if a file exist on the remote server
    >>> ubuntu_server.exists

    >>> # Checks if a folder exist on the remote server
    >>> ubuntu_server.dir_exists(location)

    >>> # Create folder if it does not exist on the remote server
    >>> ubuntu_server.dir_ensure(location, recursive=False)

    >>> # Creates file/folder or Delete file/folder on the remote server
    >>> ubuntu_server.make_or_del

    >>> # Create symbolic link
    >>> ubuntu_server.create_symbolic_link

To see the usage and parameters of all this methods please see the API documentation.

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

    >>> # Stop nginx
    >>> ubuntu_server.service_stop('nginx')

    >>> # You can also Restart(stop/start) nginx
    >>> ubuntu_server.service_restart('nginx')

    >>> # Reload after changing nginx config
    >>> ubuntu_server.service_reload('nginx')

    >>> # Check nginx status
    >>> ubuntu_server.service_status('nginx')

    >>> # uninstall nginx if you are an apache guy
    >>> # ubuntu_server.uninstall_package('nginx')


Bring it all together
=======================
Now that we have installed nginx and its up and running just fine,
lets setup our custom domain and upload our ssl certs so that our
site can now run using our site domain name over ``https``::

    >>> from os.path import as pjoin

    >>> # SSL settings
    >>> local_ssl_tar_file = "ssl.tar.gz"
    >>> remote_ssl_dir = "/etc/nginx/ssl/"
    >>> remote_tmp_ssl_dir = "/tmp/ssl/"
    >>> remote_ssl_tar_file = pjoin(remote_tmp_ssl_dir,
    ...                            local_ssl_tar_file)

    >>> # Create tmp folder(/tmp/ssl) to hold our cert
    >>> ubuntu_server.dir_ensure(remote_tmp_ssl_dir)

    >>> # Create final folder(/etc/nginx/ssl) to hold our cert
    >>> ubuntu_server.dir_ensure(remote_ssl_dir)

    >>> # Upload ssl cert to our server's /tmp/ssl
    >>> ubuntu_server.put(local_path=local_ssl_tar_file,
    ...                   remote_path=remote_tmp_ssl_dir,
    ...                   use_sudo=True)

    >>> # Uncompress ssl tar file and place content in nginx dir
    >>> ubuntu_server.uncompress(remote_ssl_tar_file,
                                 output_dir=remote_ssl_dir)

    >>> # Clean up by deleting the tar file
    >>> ubuntu_server.make_or_del(remote_ssl_tar_file,
    ...                           make=False,
    ...                           use_sudo=True)


From the code above we uploaded our ssl cert from our workstation
to our remote server, then placed it in a location where nginx can
begin to use it.


Next we will create a configuration for our site and load it so nginx
knows where to server our site from lets::


    >>> # mydomain settings

    >>> local_zip_file = "mydomain.com.conf.zip"

    >>> remote_tmp_zip_file = pjoin("/tmp", local_zip_file)
    >>> remote_config_file = '/etc/ngix/sites-available/mydomain.com.conf'
    >>> remote_enable_file = '/etc/ngix/sites-enable/mydomain.com.conf'

    >>> # Upload config for mydomain.com
    >>> ubuntu_server.put(local_path=local_zip_file,
    ...                   remote_path="/tmp/",
    ...                   use_sudo=True)

    >>> # Unzip config file
    >>> ubuntu_server.uncompress(remote_tmp_zip_file, file_type="zip")

    >>> # Clean up by deleting the zip file now after unzipping it
    >>> ubuntu_server.make_or_del(remote_tmp_zip_file, make=False, use_sudo=True)

    >>> # Enable Nginx
    >>> ubuntu_server.create_symbolic_link(remote_config_file, remote_enable_file)

    >>> # Reload new nginx config
    >>> ubuntu_server.service_reload('nginx')


Complete!
=========

This has been a minimal walk through of the fab-objects API,
for a more complete list of methods see the API docs for more information.
