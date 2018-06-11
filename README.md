# fabobjects

A collection of simple python classes for executing remote task using Fabric.

#### Table of Contents

1. [About](#about)
2. [App Description - What this library does and why it is useful](#app-description)
3. [Installation - The basics of getting started with the fabobjects](#installation)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Documentation - For additional information see the docs](#documentation)
7. [Contributors - Everyone is welcome to contribute](#contributors)


## About

Sysadmin is not so fun for everyone and command line could be intimidating for some developers. Different operating
systems do things differently and everyone of them seems to require a steep learning curve. I wanted to create a simple
python library where any python developer manage any os and deploy apps to the server without the need of understanding
the underlining system.

## App Description

Python developers want to spend time developing apps and not spending time administering a server or endless configuration before they can afford to hire a competent sysadmin.
Fabobjects makes it simple for python developers to easily secure a server and deploy their apps using pure python and minimal code.

## Installation

```bash
pip install git+https://github.com/abiolarasheed/fabobjects.git
```

## Usage

This sample assumes you are using a fresh server created in the cloud with just `root` access.
We will create an `admin user` grant him\her sudo powers, then harden the server.

```python
    >>> from os import environ
    >>> from fabobjects.distros import CentOS, Debian, FreeBsd, Ubuntu

    >>> root_user = "root"
    >>> # some providers give you the root when instance is created so we login with it on first login
    >>> my_pc_ip = "51.171.200.9" # your fixed ip address if you have one else just use None
    >>> hostname = "sandbox"      # Any name you want to give to your box

    >>> # The domain name you have already paid for and you need to point your dns to the address bellow
    >>> domain_name = "example.com"
    >>> remote_server_ip = '104.216.741.72' # The ip provided by your cloud provider for this server instance
    >>> admin_email = environ.get("ADMIN-EMAIL")
    >>> admin_user = environ.get("ADMIN-USER")  # The user we will create and use to login after first login
    >>> password = environ.get("SANDBOX-PASSWORD")

    >>> # Create a dict so you can reuse it
    >>> config_dict = dict(hostname=hostname, domain_name=domain_name,
                           ip=remote_server_ip, user=root_user, password=password)

    >>> # Create server instance
    >>> centos_server = CentOS(**config_dict)
    >>> debian_server = Debian(**config_dict)
    >>> freebsd_server = FreeBsd(**config_dict)
    >>> ubuntu_server = Ubuntu(**config_dict)

    >>> ubuntu_server.uptime()  # Check how long server has been on
    '19:08:47 up 1 min,  1 user,  load average: 0.32, 0.59, 0.27'

    >>> # For basic server hardening just call the harden_server method and you ready to go!

    >>> centos_server.harden_server(user=admin_user)
    >>> # Do this if you already passed in the `email` and `my_pc_ip` when initializing

    >>> debian_server.harden_server(user=admin_user, user_ip=my_pc_ip, email=admin_email)

    >>> freebsd_server.harden_server(user=admin_user, user_ip=my_pc_ip, email=admin_email)

    >>> ubuntu_server.harden_server(user=admin_user, user_ip=my_pc_ip, email=admin_email)

    >>> freebsd_server.install_package("nginx")  #  Install single application

    >>> centos_server.install_package("redis postgres rabbitmq")  #  Install multiple application

    >>> ubuntu_server.uninstall_package("mysql")  #  uninstall single application

```

To install applications on your server using the example servers created above:

```python
    >>> from fabobjects.apps.django import DjangoApp
    >>> from fabobjects.apps.nginx import NginxServer
    >>> from fabobjects.apps.postgres import PostgresServer
    >>> from fabobjects.apps.redis import RedisServer

    >>> # Lets deploy a django app with postgres, redis, nginx all on a single server box.
    >>> postgres = ubuntu_server.create_app(PostgresServer)
    >>> # Instantiate a postgres server, this will not trigger a deployment or installation

    >>> nginx = ubuntu_server.create_app(NginxServer)
    >>> # Instantiate an nginx server, this will not trigger a deployment or installation

    >>> redis = ubuntu_server.create_app(RedisServer)
    >>> # Instantiate a redis server, this will not trigger a deployment or installation

    >>> django_app = ubuntu_server.create_app(DjangoApp)
    >>> # Instantiate a django app, this will not trigger a deployment or installation

    >>> # Now lets add the apps to the list of apps the server knows about
    >>> [ubuntu_server.add_app(app) for app in [postgres, redis, nginx, django_app]]

    >>> # Finally install and configure all
    >>> ubuntu_server.deploy_all()
    >>> # Install and configure all app to this server, note this will be done sequentially

```

## Limitations

This app has been tested on the following platforms:

* Ubuntu 14.04, 16.04, 18.04

## Documentation

## Contributors

The list of contributors can be found at: [https://github.com/abiolarasheed/fabobjects/graphs/contributors](https://github.com/abiolarasheed/fabobjects/graphs/contributors)
