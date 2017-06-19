#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reads in Certificate and CA manifest configuration and manages
OpenSSL keys, certificates, and authorities in various formats and stores.

Usage: certpy [options] <manifest_path>

    <manifest_path> is the path to the certificate and authority manifest config file(s).
                    If this is a directory, then all files that match --manifest-glob
                    (default '*.certs.yaml') will be loaded as manifests.

Options:
    -h --help                   Show this help message and exit.
    -d --working-dir            cd to this directory before generating anything.
                                This allows relative file paths in the manifest to
                                be generated in a different location than the current cwd.
    -G --generate-certs         Generate all certificate (excluding CA certs).
    -A --generate-authorities   Generate all CA certficiate files.
    -F --force                  If given a generate option without --force, any existing files will not
                                be overwritten.  If want to overwrite files, provide --force.
    -v --verbose                Turn on verbose debug logging.
"""

from docopt import docopt

from pprint import pprint # TODO: remove

from certpy import instantiate_manifest, setup_logging


import logging

log = logging.getLogger('certpy')


def authorities_status_string(authorities):
    s = '--- Authorities ---\n'
    for name, ca in authorities.items():
        s += '{}({}):\n'.format(ca.__class__.__name__, ca.name)
        s += '{}\n'.format(ca.ca_cert.status_string())
    return s


def certificates_status_string(certificates):
    s = '--- Certificates ---\n'
    for name, cert in certificates.items():
        s += '{}\n'.format(cert.status_string())
    return s


def generate_authorities(authorities, force=False):
    # generate all authorities
    for name, ca in authorities.items():
        if hasattr(ca, 'generate'):
            try:
                ca.generate(force=force)
            except NotImplementedError as e:
                logging.warn('{} does not support generation, skipping.'.format(ca))

def generate_certificates(certificates, force=False):
    for name, cert in certificates.items():
        cert.generate(force=force)

def main():
    # parse arguments with docopt
    args = docopt(__doc__)

    setup_logging()

    loaded_manifest = instantiate_manifest(args['<manifest_path>'])
    authorities = loaded_manifest['authorities']
    certificates = loaded_manifest['certificates']


    # TODO: implement --working-dir

    if args['--generate-authorities']:
        log.info('Generating all authorities declared in {} with force={}'.format(
            args['<manifest_path>'], args['--force'])
        )
        generate_authorities(authorities, force=args['--force'])

    print('\n' + authorities_status_string(authorities))

    if args['--generate-certs']:
        log.info('Generating all certificates declared in {} with force={}'.format(
            args['<manifest_path>'], args['--force'])
        )
        generate_certificates(certificates, force=args['--force'])

    print(certificates_status_string(certificates))

if __name__ == '__main__':
    main()