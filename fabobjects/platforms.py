# coding: utf-8
# TODO: Add more distros

__all__ = ['is_debian', 'is_redhat', 'auto_detect_os']


debain = ['astra-linux', 'canaima', 'collax', 'cumulus', 'linux', 'damn', 'small',
          'linux', 'debian', 'jp', 'doudoulinux', 'embedded', 'debian', 'euronode',
          'finnix', 'grml', 'kanotix', 'knoppix', 'linex', 'linspire', 'linux',
          'advanced', 'lmde', 'mepis', 'ordissimo', 'parsix', 'gnu/linux', 'pureos',
          'rays', 'lx', 'aptosid', 'ubuntu', 'univention', 'corporate', 'server',
          'xandros'
          ]


red_hat = ['centos', 'rosa', 'enterprise', 'linux', 'server', 'scientific', 'linux',
           'clearos', 'oracle', 'linux', 'yellow', 'dog', 'linux', 'fedora', 'redhat',
           'rhel', 'suse', 'unbreakable', 'linux'
           ]


def is_debian(distro):
    """
    Return True if the given distro is a debian.
    """
    name = distro.lower()
    return name in debain


def is_redhat(distro):
    """
    Return True if the given distro is a redhat linux.
    """
    name = distro.lower()
    return name in red_hat


def auto_detect_os(distro):
    """
    Auto detect os flavor.
    """
    if is_debian(distro):
        return 'Debian'

    if is_redhat(distro):
        return 'Redhat'

    return 'Unknown'
