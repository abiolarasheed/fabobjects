#!/usr/bin/env python
from setuptools import setup, find_packages

DESCRIPTION = "A collection of simple python classes for executing remote task using Fabric."

with open('README.md') as f:
    LONG_DESCRIPTION = f.read()


install_requires = [
    'argparse==1.2.1',
    'boto==2.36.0',
    'cuisine==0.7.4',
    'ecdsa==0.13',
    'Fabric==1.10.1',
    'paramiko==1.15.2',
    'pycrypto==2.6.1',
    'requests==2.5.1',
    'wsgiref==0.1.2',
]


setup(
    name='fabobjects',
    version='0.1-dev',
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author='Abiola Rasheed',
    author_email='rasheed.abiola3@gmail.com',
    url='',
    license='BSD',
    platforms=["any"],
    packages=find_packages(),
    test_suite="fabobjects.tests",
    install_requires=install_requires,
    tests_require=[''],
    classifiers=[
        'Development Status :: 1 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development',
        'Topic :: Software Development :: Build Tools',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Clustering',
        'Topic :: System :: Software Distribution',
        'Topic :: System :: Systems Administration',
    ],
)
