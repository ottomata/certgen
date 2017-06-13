# -*- coding: utf-8 -*-

import logging
import os
import os.path
import subprocess
import yaml    # PyYAML (python-yaml)

from .util import mkdirs, run_command, openssl, get_class_logger

import logging

# TODO make this configurable?
# DefaultKeyClass = RSAKey


class Key(object):
    def __init__(self, name, path, password=None, **kwargs):
        self.name = name
        self.path = os.path.abspath(path)
        self.password = password
        # Private Key file in .pem format
        self.key_file = os.path.join(self.path, '{}.key'.format(self.name))

        self.log = get_class_logger(self)

    def exists(self):
        return os.path.exists(self.key_file)

    def check_force_generate(self, force):
        if self.exists() and not force:
            self.log.warn(
                '{} already exists, skipping key generation...'.format(self.key_file)
            )
            return False
        else:
            return True

    def generate(self, force=False):
        raise NotImplementedError(
            'Cannot generate Key of unknown algorithm type.  Use a subclass.', self
        )

    def __repr__(self):
        return '{}(name={}, file={})'.format(self.__class__.__name__, self.name, self.key_file)



class RSAKey(Key):
    def __init__(self, name, path, password=None, key_size=2048, **kwargs):
        self.key_size = key_size
        super().__init__(name, path, password)

    def generate(self, force=False):
        if not self.check_force_generate(force):
            return False

        mkdirs(self.path)

        command = [openssl, 'genrsa', '-out', self.key_file]
        if self.password:
            command += ['-passout', 'pass:{}'.format(self.password)]
        command += [str(self.key_size)]

        self.log.info('Generating key')
        if not run_command(command):
            raise RuntimeError('RSA key generation failed')

        if not self.exists():
            raise RuntimeError(
                'Key generation succeeded but key file does not exist. '
                'This should not happen', self
            )

        return self.key_file

    def __repr__(self):
        return '{}(name={}, file={}, size={})'.format(
            self.__class__.__name__, self.name, self.key_file, self.key_size
        )


class ECKey(Key):
    def __init__(self, name, path, password=None, asn1_oid='prime256v1', **kwargs):
        self.asn1_oid = asn1_oid
        super().__init__(name, path, password)

    def generate(self, force=False):
        if not self.check_force_generate(force):
            return False

        mkdirs(self.path)

        command = [openssl, 'ecparam', '-genkey', '-name', self.asn1_oid, '-out', self.key_file]

        self.log.info('Generating key')
        # Generate the keyfile with no password
        if not run_command(command):
            raise RuntimeError('EC key generation failed', self)

        # Now encrypt the key with a password
        if self.password:
            command = [
                openssl, 'ec',
                '-in', self.key_file,
                '-out', self.key_file,
                '-des3', '-passout', 'pass:{}'.format(self.password)
            ]
            self.log.info('Encrypting key with password')

            if not run_command(command):
                raise RuntimeError('EC key file password encryption failed')

        if not self.exists():
            raise RuntimeError(
                'Key generation succeeded but key file does not exist. '
                'This should not happen', self
            )

        return self.key_file

    def __repr__(self):
        return '{}(name={}, file={}, asn1_oid={})'.format(
            self.__class__.__name__, self.name, self.key_file, self.asn1_oid
        )
