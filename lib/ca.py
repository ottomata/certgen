# -*- coding: utf-8 -*-

from .key import Key, RSAKey
from .certificate import Certificate, Subject, default_subject # TODO REMOVE
from .util import openssl, run_command, mkdirs, get_class_logger

import logging
import os
import tempfile


#  TODO do we need a CA base class?  all we need is an object with sign(cert) and verity(cert|crt_file) methods.

class CA(object):
    """Base class for CAs"""
    def __init__(self, cert, **kwargs):
        #  TODO make these names match?
        self.ca_crt = cert
        self.name = self.ca_crt.name
        self.log = get_class_logger(self)

    def sign(self, csr_file, common_name):
        # return crt_file path?
        pass



# TODO: should I use openssl ca and a ca.conf file to do this?!?
class SelfSigningCA(CA):
    def __init__(self, cert, **kwargs):
        super().__init__(cert)

    def sign(self, certificate):
        command = [
            openssl,
            'x509',
            '-req',
            '-CAcreateserial',
            '-CA', self.ca_crt.crt_file,
            '-CAkey', self.ca_crt.key.key_file,
            '-in', certificate.csr_file,
            '-out', certificate.crt_file
        ]
        if certificate.digest:
            command += ['-{}'.format(certificate.digest)]
        if certificate.expiry_days:
            command += ['-days', str(certificate.expiry_days)]
        # If this certificate's CSR was created with a CSR config file,
        # then we should also pass the same config file when signing.
        # This ensure that the requested SANs are included in the signed
        # certificate.
        if certificate.csr_conf_file:
            # TODO: perhaps somehow parameterize what extensions to use?
            command += ['-extfile', certificate.csr_conf_file]
        if certificate.dns_alt_names:
            command+= ['-extensions', 'v3_req']

        logging.debug('Signing CSR from {} with {}'.format(certificate.csr_file, self))
        if not run_command(command):
            raise RuntimeError('Signing CSR {} failed'.format(certificate.csr_file))

        # TODO: return something useful?


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

    def generate(self):
        self.log.info('Generating CA certificate')
        self.ca_crt.generate()

    def __repr__(self):
        return '{}(key_file={}, crt_file={})'.format(
            self.__class__.__name__, self.ca_crt.key.key_file, self.ca_crt.crt_file
        )



class PuppetCA(object):
    """docstring for PuppetCA"""
    def __init__(
            self,
            puppet_hostname='puppet',
            puppet_port=8140,
            puppet_crt_path='/var/lib/puppet/server/ssl/ca/signed',
            puppet_sign_script='/usr/local/bin/puppet-sign-cert',
            **kwargs
        ):

        self.name = 'puppet'
        self.log = get_class_logger(self)

        self.puppet_hostname = puppet_hostname
        self.puppet_port = puppet_port
        self.puppet_sign_script = puppet_sign_script


    def sign(self, cert):
        """docstring for sign"""

        # call out to puppet_sign_cert.rb and then copy file from puppetmaster dirs into base_path
        command = [
            self.puppet_sign_script,
            '-H', self.puppet_hostname,
            '-P', str(self.puppet_port),
            cert.csr_file
        ]
        self.log.info('Submitting CSR {} to Puppet CA'.format(
            cert.csr_file,
            self.puppet_hostname,
            self.puppet_port
        ))
        if not run_command(command):
            raise RuntimeError('Signing CSR {} with Puppet CA failed'.format(cert.csr_file), self)


        # Path to the signed certificate file that puppet will generate.
        puppet_crt_file = os.path.join(self.puppet_crt_path, '{}.pem'.format(cert.name))

        # TODO: check that puppet_crt_file is exists after calling puppet sign script

        # COPY new puppet .crt (.pem) file into crt_file location
        mkdirs(cert.path)
        self.log.info('Copying puppet signed certificate from {} to {}'.format(
            puppet_crt_file, cert.crt_file
        ))
        shutil.copyfile(puppet_crt_file, cert.crt_file)
        # TODO: check that cert.crt_file exists now
