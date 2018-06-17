fab-objects: Simple Oop Dev-Tools!
==================================
**fab-objects** is a high-level Python library usefull for perfuming common Unix system administration task, by providing a
set of Python Classes for executing shell command on a remote system via SSH. It presents a unified, familiar API that allows you to logically plan deployments and maintenance.

fab-objects is a light-weight wrapper around the `Fabric <http://fabfile.org>`_ library.


.. note::

    This documentation assumes you have some python knowledge and that you are running python3.6 or above.


**fab-objects in action**::

    >>> from os import environ
    >>> from fabobjects.distros import Ubuntu
    >>> from . import server_config

    >>> # Create an ubuntu server instance
    >>> ubuntu_server = Ubuntu(**server_config)

    >>> # Update the server
    >>> ubuntu_server.update()

    >>> # Reboot the server
    >>> ubuntu_server.rebootall()

    >>> # Install your application
    >>> ubuntu_server.install_package('postgresql-9.6')


.. toctree::
   :maxdepth: 2

   tutorial


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
