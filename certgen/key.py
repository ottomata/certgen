# -*- coding: utf-8 -*-

"""
Classes for OpenSSL private key generation.  Extend the base Key class if you need
to generate a key of a type not yet supported here.
"""

import os.path

from .util import mkdirs, run_command, openssl, get_class_logger

__all__ = ('Key', 'RSAKey', 'ECKey')


class Key(object):
    """
    Base class for Key objects.  This just sets up common instance variables
    and includes some convenience methods.
    """
    def __init__(self, name, path, password=None, **kwargs):
        """
        :param name
        :param path path in which to look for and generate files
        :param password key password
        """

        self.name = name
        self.path = os.path.abspath(path)
        self.password = password
        # Private Key file in .pem format
        self.key_file = os.path.join(self.path, '{}.key'.format(self.name))

        self.log = get_class_logger(self)

    def exists(self):
        """
        Checks that this Key exists at the expected key file path.
        """
        return os.path.exists(self.key_file)

    def check_force_generate(self, force):
        """
        DRY method for checking if generate should be allowed even if the key file already exists.
        :param force If True, this returns True
        :return True or False if generation should be allowed
        """
        if self.exists() and not force:
            self.log.warn(
                '{} already exists, skipping key generation...'.format(self.key_file)
            )
            return False
        else:
            return True

    def generate(self, force=False):
        """
        Implement this method to support generation of your Key subclass.
        """
        raise NotImplementedError(
            'Cannot generate Key of unknown algorithm type.  Use a subclass.', self
        )

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.name)



class RSAKey(Key):

    def __init__(self, name, path, password=None, key_size=2048, **kwargs):
        """
        Helps with generation of RSA key files.
        :param name
        :param path path in which to look for and generate files
        :param password key password
        :param key_size RSA key size
        """
        self.key_size = key_size
        super().__init__(name, path, password)

    def generate(self, force=False):
        """
        Generates the key file.
        :param force if True, the key will be re-generated even if the key file exists.
        """
        if not self.check_force_generate(force):
            return False

        mkdirs(self.path)

        command = [openssl, 'genrsa', '-out', self.key_file]
        if self.password:
            command += ['-passout', 'pass:{}'.format(self.password)]
        command += [str(self.key_size)]

        self.log.info('Generating RSA key')
        if not run_command(command):
            raise RuntimeError('RSA key generation failed')

        if not self.exists():
            raise RuntimeError(
                'Key generation succeeded but key file does not exist. '
                'This should not happen', self
            )


class ECKey(Key):
    """
    Helps with generation of Eliptic Curve key files.
    :param name
    :param path path in which to look for and generate files
    :param password key password
    :param asn1_oid
    """
    def __init__(self, name, path, password=None, asn1_oid='prime256v1', **kwargs):
        self.asn1_oid = asn1_oid
        super().__init__(name, path, password)

    def generate(self, force=False):
        """
        Generates the key file.
        :param force if True, the key will be re-generated even if the key file exists.
        """
        if not self.check_force_generate(force):
            return False

        mkdirs(self.path)

        command = [openssl, 'ecparam', '-genkey', '-name', self.asn1_oid, '-out', self.key_file]

        self.log.info('Generating EC key')
        # Generate the keyfile with no password
        if not run_command(command):
            raise RuntimeError('EC key generation failed', self)

        # Now encrypt the key with a password, overwriting the original
        # passwordless key.
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
