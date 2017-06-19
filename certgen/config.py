# -*- coding: utf-8 -*-

import os
import logging
import importlib
from yamlreader import yaml_load

#  TODO make new classes loadable from plugins
from .certificate import *
from .key import *
from .ca import *

__all__ = ('load_manifests', 'instantiate_manifest') # TODO: validate

# TODO: use relative paths in config???

default_config = {
    'authorities': {},
    'certs': {}
}

log = logging.getLogger('config')

def load_manifests(path, glob='*.certs.yaml'):
    """
    Given a directory, this will load all files matching config_file_glob
    as YAML and then recursively merge them into a single config hash
    using the yamlreader library.

    :param glob default: '*.certs.yaml'
    :return config dict
    """
    path = os.path.abspath(path)

    # If this is a single file, then no need to use the glob.
    if os.path.isfile(path):
        log.info('Loading certificate and authority manifest from {}'.format(path))
        return yaml_load(path, default_config)
    # Else it is a directory, probably containing multiple manifest files.
    # Load any file that matches path glob.
    else:
        path_glob = os.path.join(path, glob)
        log.info('Loading all certificate and authority manifests in {}'.format(path_glob))
        return yaml_load(path_glob, default_config)


    # TODO: validate loaded manifest config against jsonschema


def instantiate_manifest(manifest):
    """
    Given a certificate maniest dict object (usually loaded from a yaml file), containing
    definitions of certificates and CAs to manage, instantiate them into objects.

    :param manifest manifest of all authority and certificate configs.  CAs, Certificate, and Key
                    classes will all be instantiated based on this configuration and returned.

    :return dict    of the form { 'authorities': {...}, 'certificates': {...} }, where each
                    declared CA and Certificate will be keyed by name in the appropriate dict.
    """
    authorities = instantiate_authorities(manifest['authorities'])
    certificates = instantiate_certs(manifest['certs'], authorities)

    return {
        'authorities': authorities,
        'certificates': certificates
    }



def instantiate_cert(cert_config, authorities={}):
    """
    Given a cert config manifest, instantiate the Certificate class and return it.
    If this cert has a CA configured, that CA should already be instantiated in
    the authorities hash, keyed by the CA named in the cert_config.

    :param certs_manifest   cert manifest config keyed by name to instantiate.
                            Make sure that cert_config['name'] is set.
    :param authorities      dict of CA instances keyed by ca name.


    :return Certificate
    """
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

def instantiate_certs(certs_manifest, authorities):
    """
    This will return a dict of Certficate instances keyed by name
    representing all of the certs declared in certs_manifest.
    If a cert declares a ca, make sure that a CA instance exists
    in the authorities dict, keyed by the same name as the ca
    that the cert config specifies.

    :param certs_manifest   dict of cert manifest config keyed by name to instantiate.
    :param authorities      dict of CA instances keyed by ca name.

    :return dict            dict of Certificate instances keyed by name.
    """
    certs = {}
    for name, cert_config in certs_manifest.items():
        # Set cert_config['name'] to this manifest cert key name.
        cert_config['name'] = name

        cert = instantiate_cert(cert_config, authorities)
        certs[name] = cert
    return certs


#  TODO change param to authority_config
def instantiate_authorities(authorities_manifest):
    """
    Given a manifest of authority config, this will instantiate each as a CA instance.

    :param authorities_manifest dict of CA config keyed by CA name.
    :return dict                dict of CA instances keyed by name.
    """
    authorities = {}
    # TODO: s/ca_config/authority_config?
    for name, ca_config in authorities_manifest.items():
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


def validate(config):
    pass
    # TODO: json schema? Maybe!



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
    elif module_class_name in locals():
        return locals()[module_class_name]
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

    Make sure that the fully qualified class name that you pass is in
    PYTHONPATH.  Example:

        $ tree /usr/local/lib/certgen
        /usr/local/lib/certgen/
        └── ext
            └── key.py

        $ head -n 1 /usr/local/lib/certgen/ext/key.py
        class DSAKey(Key):

        $ export PYTHONPATH=/usr/local/lib/certgen

        ...
        instantiate('ext.key.DSAKey')

    :param class_name fully qualified class name
    :return instance of class
    """
    return get_class(class_name)(**kwargs)
