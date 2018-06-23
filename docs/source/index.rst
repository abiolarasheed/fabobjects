fab-objects: A Simple Python DevOps-Tool!
==========================================
**fab-objects** is a high-level Python library useful for perfuming common Unix system administration task, by providing
a set of Python Classes for executing shell command on a remote system via SSH. It presents a unified, familiar API that
allows you to logically plan deployments and maintenance.

fab-objects is a light-weight wrapper around the `Fabric <http://fabfile.org>`_ library.


.. note::

    This documentation assumes you have some python knowledge, that you are running
    python3.6 or above and that your ssh key is located in ``~/.ssh`` directory.


**fab-objects in action**::

    >>> from os import environ
    >>> from fabobjects import Ubuntu
    >>> from myapp.conf import server_config

    >>> # Create an ubuntu server instance
    >>> ubuntu_server = Ubuntu(**server_config)

    >>> # Update the server
    >>> ubuntu_server.update()

    >>> # Reboot the server
    >>> ubuntu_server.rebootall()

    >>> # Install your application
    >>> ubuntu_server.install_package('postgresql-9.6')


We can run this same code with a different OS by calling the same method on the distro instance
and all should just work fine. For example on a FreeBSD::


    >>> from os import environ
    >>> from fabobjects import FreeBSD
    >>> from . import server_config

    >>> # Create a freebsd server instance
    >>> free_bsd_server = FreeBSD(**server_config)

    >>> # Update the server
    >>> free_bsd_server.update()

    >>> # Reboot the server
    >>> free_bsd_server.rebootall()

    >>> # Install your application
    >>> free_bsd_server.install_package('postgresql-9.6')


.. toctree::
   :maxdepth: 2

   tutorial
   applications


The API Documentation
-----------------------

If you are looking for information about the API details on a specific class, method or function, checkout our
API documentation:

.. toctree::
    :maxdepth: 1
    :glob:

    api/*


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
