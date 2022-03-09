#!/usr/bin/env python3

from setuptools import setup, find_packages
import os


with open("README.md", "r") as fh:
    long_description = fh.read()

VERSION = '0.0.3'
DESCRIPTION = 'Package to set up a credentials provider with wSock.'
LONG_DESCRIPTION = long_description

# Setting up
setup(
    name="wsock_secrets_provider",
    version=VERSION,
    author="Verifiably",
    author_email="atul@verifiably.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=[
        'cbor2==5.2.0',
        'cose==0.9.dev2',
        'cryptography==3.2.1',
        'pycryptodome==3.9.9',
        'pyOpenSSL==19.1.0',
        'boto3',
        'websocket-client',
        'rel'
    ],
    python_requires='>=3.8',
    include_package_data = True,
    keywords=['python', 'web-socket', 'credentials'],
    url='https://github.com/verifiably/wsock-secrets-provider',
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ]
)
