# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

try:
    long_description = open('README.md').read()
except IOError:
    long_description = ''

setup(
    name='certpy',
    version='0.1.0',
    description='OpenSSL Certificate Manager',
    license='Apache',
    author='Andrew Otto',
    packages=find_packages(),
    install_requires=[
        'docopt'
        'pyyaml',
        'yamlreader',
    ]
    long_description=long_description,
    scripts=(),
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.3',
    ]
)
