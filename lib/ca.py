# -*- coding: utf-8 -*-

from .key import Key, RSAKey
from .certificate import Certificate, Subject, default_subject # TODO REMOVE
from .util import openssl, run_command, mkdirs

import logging



class CA(object):
    """Base class for CAs"""
    # def __init__(self, name, path, key=None):
    #     self.name = name
    #     self.path = path
    #     self.key = key

    def sign(self, csr_file, common_name):
        # return crt_file path?
        pass


class SelfSigningCA(CA):
    def __init__(self, ca_crt):
        self.ca_crt = ca_crt

    def sign(self, csr_file, out_crt_file, expiry_days=None):
        command = [
            openssl,
            'x509',
            '-req',
            '-CAcreateserial',
            '-CA', self.ca_crt.crt_file,
            '-CAkey', self.ca_crt.key.key_file,
            '-in', csr_file,
            '-out', out_crt_file
        ]
        if expiry_days:
            command += ['-days', str(expiry_days)]

        logging.debug('Signing CSR from {} with {}'.format(csr_file, self))
        if not run_command(command):
            raise RuntimeError('Signing CSR {} failed'.format(csr_file))

        # TODO: return new Certificate()?


    def verify(self, crt_file):
        # Verify that signature was good!
        command = [
            openssl,
            'verify',
            '-CAfile', self.ca_crt.crt_file,
            crt_file
        ]
        if not run_command(command):
            raise RuntimeError('Certificate {} verification failed with {}'.format(
                self.crt_file, self
            ))

    def __repr__(self):
        return '{}(key_file={}, crt_file={})'.format(
            self.__class__.__name__, self.ca_crt.key.key_file, self.ca_crt.crt_file
        )



class PuppetCA(CA):
    """docstring for PuppetCA"""
    def __init__(
            self,
            name,
            base_path,
            puppet_hostname,
            puppet_port,
            puppet_cert_path='/var/lib/puppet/ssl',
            puppet_sign_script='/usr/local/bin/puppet-sign-cert',
            key=None,
        ):
        # super(PuppetCA, self).__init__(name, base_path, key)
        self.puppet_hostname = puppet_hostname
        self.puppet_port = puppet_port
        self.puppet_cert_path = puppet_cert_path
        self.puppet_sign_script = puppet_sign_script


    def sign(self, csr_file, common_name):
        """docstring for sign"""

        # call out to puppet_sign_cert.rb and then copy file from puppetmaster dirs into base_path
        command = [
            self.puppet_sign_script,
            '-H', self.puppet_hostname,
            '-P', self.puppet_port,
            csr_file
        ]
        if not run_command(command):
            raise RuntimeError('Signing of {} with Puppet at {}:{} failed'.format(
                csr_file,
                self.puppet_hostname,
                self.puppet_port
            ))

        # Path to the signed certificate file that puppet will generate.
        puppet_crt_file = os.path.join(self.puppet_cert_path, '{}.pem'.format(common_name))
        dest_dir = os.path.join(self.base_path, common_name)
        dest_crt_file = os.path.join(dest_dir, '{}.crt'.format(common_name))

        # TODO: check that puppet_cert_file is created

        # COPY new puppet .crt (.pem) file into dest_dir
        mkdirs(dest_dir)
        shutil.copyfile(puppet_crt_file, dest_crt_file)

    def generate(self):
        raise RuntimeError("Cannot generate a Puppet CA")
