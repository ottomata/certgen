# -*- coding: utf-8 -*-

import os
import logging
import importlib
from yamlreader import yaml_load

#  TODO make new classes loadable from plugins
from .certificate import *
from .key import *
from .ca import *

# TODO: use relative paths in config???

default_config = {
    'authorities': {},
    'certs': {}
}

log = logging.getLogger('config')

def load_config(config_directory, glob='*.certs.yaml'):
    """
    Given a directory, this will load all files matching config_file_glob
    as YAML and then recursively merge them into a single config hash
    using the yamlreader library.

    :param glob default: '*.certs.yaml'
    :return config dict
    """
    config_directory = os.path.abspath(config_directory)
    config_path_glob = os.path.join(config_directory, glob)
    log.info('Loading all config from {}'.format(config_path_glob))
    return yaml_load(config_path_glob, default_config)


def get_class(module_class_name):
    """
    Returns module_class_name as a class.  This is useful for instantiating
    a class by its dotted string name.

    :param module_class_name Fully qualified name, e.g. 'my.module.ClassName'.  This must
                             either be in globals(), or be importable via importlib.import_module

    :return Class
    """
    if module_class_name in globals():
        return globals()[module_class_name]
    elif '.' in module_class_name:
        module_name, class_name = module_class_name.rsplit('.', 1)
        module = importlib.import_module(module_name)
        return getattr(module, class_name)
    else:
        raise RuntimeError(
            'Cannot dynamically import {}, '
            'it is not in globals() or importable'.format(module_class_name)
        )


def instantiate(class_name, **kwargs):
    """
    Given a fully qualified module and class name, this returns a new
    instance of the class with kwargs passed to the constructor.

    :param class_name fully qualified class name
    :return instance of class
    """
    return get_class(class_name)(**kwargs)


def instantiate_cert(cert_config, authorities={}):

    # If we have a special config for this key (that is not the default RSAKey)
    # that Certificate will generate if not given a key, then we need to
    # instantiate a new key now.
    if 'key' in cert_config:
        key_config = cert_config['key']
        key_config.setdefault('name', cert_config['name'])
        key_config.setdefault('path', cert_config['path'])
        key_config.setdefault('password', cert_config['password'])

        cert_config['key'] = instantiate(key_config['type'], **key_config)

    if 'ca' in cert_config:
        ca_name = cert_config['ca']

        if ca_name not in authorities:
            raise RuntimeError(
                '{name} cert\'s CA is set to {ca}, but authority with '
                'name {ca} is not declared in authorities.'.format(
                    name=name, ca=ca_name
                ))

        cert_config['ca'] = authorities[ca_name]

    return Certificate(**cert_config)

def instantiate_certs(certs_config, authorities):
    certs = {}
    for name, cert_config in certs_config.items():
        cert_config['name'] = name

        cert = instantiate_cert(cert_config, authorities)
        certs[name] = cert
    return certs



#  TODO change param to authority_config
def instantiate_authorities(authorities_config):
    authorities = {}
    # TODO: s/ca_config/authority_config?
    for name, ca_config in authorities_config.items():
        ca_config['name'] = name

        print(ca_config)
        # Instantiate the CA cert for this CA IF it has one
        if 'cert' in ca_config:
            ca_cert_config = ca_config['cert']
            ca_cert_config['name'] = name
            ca_cert = instantiate_cert(ca_cert_config)
            ca_config['cert'] = ca_cert

        ca = instantiate(ca_config['type'], **ca_config)
        authorities[name] = ca

    return authorities

def instantiate_all(config):
    authorities = instantiate_authorities(config['authorities'])
    certificates = instantiate_certs(config['certs'], authorities)

    return {
        'authorities': authorities,
        'certificates': certificates
    }




def validate(config):
    pass
    # TODO: json schema? Maybe!
