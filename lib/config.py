# -*- coding: utf-8 -*-

import os
import logging
import importlib
from yamlreader import yaml_load

#  TODO make new classes loadable from plugins
from .certificate import *
from .key import *
from .ca import *

config_file_glob = '*.certs.yaml'

default_config = {
    'authorities': {},
    'certs': {}
}

def load(config_directory):
    config_directory = os.path.abspath(config_directory)
    config_path_glob = os.path.join(config_directory, config_file_glob)
    logging.info('loading all config from {}'.format(config_path_glob))
    return yaml_load(config_path_glob, default_config)


def get_class(module_class_name):
    if module_class_name in globals():
        return globals()[module_class_name]

    elif '.' in module_class_name:
        module_name, class_name = module_class_name.rsplit('.', 1)
        module = importlib.import_module(module_name)
        return getattr(module, class_name)
    else:
        # TODO
        raise RuntimeError('not sure what to do here yet')

def get_instance(class_name, **kwargs):
    return get_class(class_name)(**kwargs)






#
# def instantiate_key(key_config):
#     return get_class(key_config['type'])(**key_config)
#
# def instantiate_authority(authority_config):
#     return get_class(authority_config['type'])(**authority_config)

def instantiate_cert(cert_config, authorities={}):
    key_config = cert_config['key']
    if 'name' not in key_config:
        key_config['name'] = cert_config['name']
    if 'path' not in key_config:
        key_config['path'] = cert_config['path']

        #  TODO just set cert_config['key'] = key?
    key = get_instance(key_config['type'], **key_config)
    del cert_config['key']

    if 'ca' in cert_config:
        ca_name = cert_config['ca']

        if ca_name not in authorities:
            raise RuntimeError(
                '{name} cert\'s CA is set to {ca}, but authority with '
                'name {ca} is not declared in authorities config'.format(
                    name=name, ca=ca_name
                ))

        cert_config['ca'] = authorities[ca_name]

    return Certificate(
        key=key,
        **cert_config
    )

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

        # Instantiate the CA cert for this CA IF it has one
        if 'cert' in ca_config:
            ca_cert_config = ca_config['cert']
            ca_cert_config['name'] = name
            ca_cert = instantiate_cert(ca_cert_config)
            ca_config['cert'] = ca_cert

        ca = get_instance(ca_config['type'], **ca_config)
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
