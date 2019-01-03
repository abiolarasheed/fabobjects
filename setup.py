# coding: utf-8
from setuptools import setup, find_packages

DESCRIPTION = (
    "A collection of simple python classes for executing remote task using Fabric."
)

with open("README.md") as f:
    LONG_DESCRIPTION = f.read()


install_requires = ["Fabric3==1.14.post1", "Sphinx==1.7.5"]


setup(
    name="fabobjects",
    version="0.0.1",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author="Abiola Rasheed",
    author_email="rasheed.abiola3@gmail.com",
    url="",
    license="BSD",
    platforms=["any"],
    packages=find_packages(),
    test_suite="fabobjects.tests",
    install_requires=install_requires,
    tests_require=[""],
    classifiers=[
        "Development Status :: 1 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Clustering",
        "Topic :: System :: Software Distribution",
        "Topic :: System :: Systems Administration",
    ],
)
