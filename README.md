# fabobjects

A collection of simple python classes for executing remote task using Fabric.

#### Table of Contents

1. [About](#about)
2. [App Description - What the module does and why it is useful](#app-description)
3. [Installation - The basics of getting started with the motd module](#installation)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Limitations - OS compatibility, etc.](#limitations)
6.  [Documentation](#documentation)
7. [Contributors - Everyone is welcome to contribute](#contributors)


## About

Sysadmin is not so fun for everyone and command line could be intimidating for some developer. Different operating
system do things differently and every one of them seems to require steep learning curve. I wanted to create a simple
python library where any python developer manage any os and deploy apps to the server without the need of understanding
the underlining system.

## App Description

Python developers want to spend time developing apps and not spending time, administering a server or endless
configuration the before they hire a compitent sysadmin. Fabobjects make is simple dor python developers to easily
secure a server and deploy their apps using pure python

## Installation

```bash
pip install git+https://github.com/abiolarasheed/fabobjects.git
```

## Usage

This sample assumes you are using a fresh server created in the cloud with just `root` access.
We will create an `admin user` grant him\her sudo powers, then harden the server.

```python
    >>> from os import environ
    >>> from fabobjects.distros import CentOs, Debian, FreeBsd, Ubuntu

    >>> my_pc_ip = "192.168.1.9"
    >>> hostname = "sandbox"
    >>> domain_name = "example.com"
    >>> remote_server_ip = '192.168.1.12'
    >>> admin_email = environ.get("ADMIN-EMAIL")
    >>> admin_user = environ.get("ADMIN-USER")
    >>> password = environ.get("SANDBOX-PASSWORD")

    >>> config_dict = dict(hostname=hostname, domain_name=domain_name,
                           ip=remote_server_ip, user="root", password=password)  # Create a dict you can resuse

    >>> # Creating any server instance
    >>> centos_server = CentOs(**config_dict)
    >>> debian_server = Debian(**config_dict)
    >>> freebsd_server = FreeBsd(**config_dict)
    >>> ubuntu_server = Ubuntu(**config_dict)

    >>> ubuntu_server.uptime()  # Check how long server has been on
    '19:08:47 up 1 min,  1 user,  load average: 0.32, 0.59, 0.27'

    >>> # For basic server hardening just call the harden_server method and you ready to
    >>> # use user server in the wild
    >>> centos_server.harden_server(user=admin_user, host_ip=my_pc_ip, email=admin_email)
    >>> debian_server.harden_server(user=admin_user, host_ip=my_pc_ip, email=admin_email)
    >>> freebsd_server.harden_server(user=admin_user, host_ip=my_pc_ip, email=admin_email)
    >>> ubuntu_server.harden_server(user=admin_user, host_ip=my_pc_ip, email=admin_email)


    >>> ubuntu_server.install_package("nginx")  #  Install single application
    >>> ubuntu_server.install_package("redis postgres rabbitmq")  #  Install multiple application
    >>> ubuntu_server.uninstall_package("mysql")  #  uninstall single application
```

To install applications on your server using the example servers created above:

```python
    >>> from fabobjects.apps.django import DjangoApp
    >>> from fabobjects.apps.git import GitRepo
    >>> from fabobjects.apps.nginx import NginxServer
    >>> from fabobjects.apps.postgres import PostgresServer
    >>> from fabobjects.apps.redis import RedisServer
```

## Limitations

This app has been tested on the following platforms:

* Ubuntu 14.04, 16.04, 18.04

## Documentation

## Contributors

The list of contributors can be found at: [https://github.com/abiolarasheed/fabobjects/graphs/contributors](https://github.com/abiolarasheed/fabobjects/graphs/contributors)