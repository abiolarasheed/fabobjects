# !*-* coding:utf-8 *-*
from __future__ import unicode_literals

import time
import random
from functools import wraps
from fabric.colors import green
from fabric.api import settings
from fabric.exceptions import NetworkError


def random_password(bit=12):
    """
    Generates a random password which include numbers, letters and special characters.
    """
    numbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    small_letters = [chr(i) for i in range(97, 123)]
    cap_letters = [chr(i) for i in range(65, 91)]
    special = ["@", "#", "$", "%", "^", "&", "*", "-"]

    passwords = []
    for i in range(int(bit / 4)):
        passwords.append(random.choice(numbers))
        passwords.append(random.choice(small_letters))
        passwords.append(random.choice(cap_letters))
        passwords.append(random.choice(special))
    for i in range(int(bit % 4)):
        passwords.append(random.choice(numbers))
        passwords.append(random.choice(small_letters))
        passwords.append(random.choice(cap_letters))
        passwords.append(random.choice(special))

        passwords = passwords[:bit]
    random.shuffle(passwords)
    return str("".join(passwords))


def return_distinct_servers(servers):
    """
    Returns only one instance of a server or application.
    This will not guarantee that the server you want is the one you will get,
    it will only get them in order.
    """
    servers_hostname = []
    all_servers = []
    for server in servers:
        hostname = server.cache.get("hostname")
        if hostname in servers_hostname:
            continue
        else:
            servers_hostname.append(hostname)
            all_servers.append(server)
    return all_servers


def _print(output):
    """Prints the function being called """
    print(output)


def timing(func):
    """Times function call."""

    @wraps(func)
    def timed(*args, **kwargs):
        time_in = time.time()
        result = func(*args, **kwargs)
        timeout = time.time()
        total_time = (time_in - timeout) * 1000.0
        _print("\n{0} function took {1}0.3f ms\n".format(func.__name__, total_time))
        return result

    return timed


def log_call(func):
    """Logs any callable"""

    @wraps(func)
    def logged(*args, **kwargs):
        header = tail = "-" * len(func.__name__)
        _print(green("\n".join([header, func.__name__, tail]), bold=True))
        return func(*args, **kwargs)

    return logged


class ServerHostManager(object):
    """
    A descriptor decorator that decorates an object and exposes the instance that
    is decorated.
    """

    def __init__(self, instance_method):
        self.func = instance_method
        self.func.__name__ = instance_method.__name__

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            try:
                with settings(
                    password=instance.get_password,
                    host_string=instance._host,
                    key_filename=instance.env.key_filename,
                ):
                    result = self.func(instance, *args, **kwargs)
                return result
            except NetworkError:
                print(
                    "Unable to connect to {0} it maybe Down! \n\n\n".format(
                        instance._host
                    )
                )
            except SystemExit:
                print("Encountered an error (return code 1) while executing command")

        wrapper.__name__ = self.func.__name__
        return wrapper


server_host_manager = ServerHostManager
