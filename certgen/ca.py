# -*- coding: utf-8 -*-

"""
A CA class needs to be able to:
    1. Sign a CSR and generate a new certificate file
    2. Verify the a certificate file is signed with itself

If relevant, we also want a CA class to be able to support self generation,
i.e. a self signing root CA.

As such, a CA subclass class that can used by a Certificate should implement the following
3 methods: sign, verify, and optionally, generate.  All subclasses must also set
self.cert to a Certificate instance, even if the Certificate files cannot be
referenced or generated.  (This is needed for comprehensive status printing.)

    '''
    Given a Certificate instance cert, with a existant .csr and .key file,
    this signs the certificate, resulting in the creation of cert.crt_file.

    :param cert Certificate
    '''
    def sign(self, cert):
        ...

    '''
    Given a Certificate instance cert, this should verify that cert.crt_file
    there is signed by this CA.

    :param cert Certificate
    :return boolean
    '''
    def verify(self, cert):
        ...

    '''
    Implement this if for CAs that can generate themselves.  If the CA cannot generate
    itself, the base CA class will raise a NotImplementedError.
    Usually, generate will be implemented using a self signed Certificate (CA-less)
    instance given to your CA class' constructor.
    '''
    def generate(self):
        ...


"""


from .key import Key, RSAKey
from .certificate import Certificate, Subject, default_subject # TODO REMOVE
from .util import openssl, run_command, mkdirs, get_class_logger

import logging
import os
import tempfile

__all__ = ('CA', 'SelfSigningCA', 'PuppetCA')


class CA(object):
    """
    Base 'abstract' class for CAs.  You should implement these following methods
    in subclass CAs classes.
    """
    def __init__(self, **kwargs):
        """
        Constructor.  All CA subclass construtors should take **kwargs and
        should all set self.name.
        """
        raise NotImplementedError('__init__ not implemented for ' +  str(self))

    def generate(self, force=False):
        raise NotImplementedError('generate not implemented for ' + str(self))

    def sign(self, cert):
        raise NotImplementedError('sign not implemented for ' + str(self))

    def verify(self, cert):
        raise NotImplementedError('verify not implemented for ' + str(self))

    def __repr__(self):
        if hasattr(self, 'name'):
            return '{}({})'.format(self.__class__.__name__, self.name)
        else:
            return self.__class__.__name__


class SelfSigningCA(CA):
    """
    A SelfSigningCA uses a self-signed (CA-less) Certificate to sign
    other Certificates.
    """
    def __init__(self, cert, **kwargs):
        """
        :param cert     CA Certificate instance. This should
                        represent the CA's key and certificate files.
        """
        self.ca_cert = cert
        self.name = self.ca_cert.name
        self.log = get_class_logger(self)


    def sign(self, cert):
        """
        Signs a Certificate instance with this CA's certificate.  This requires
        that cert.csr_file has been generated and exists, as it will be used when
        signing the new certificate.

        :param cert  Certificate instance to sign.
        """
        command = [
            openssl,
            'x509',
            '-req',
            '-CAcreateserial',
            '-CA', self.ca_cert.crt_file,
            '-CAkey', self.ca_cert.key.key_file,
            '-in', cert.csr_file,
            '-out', cert.crt_file
        ]
        if cert.digest:
            command += ['-{}'.format(cert.digest)]
        if cert.expiry_days:
            command += ['-days', str(cert.expiry_days)]
        # If this certificate's CSR was created with a CSR config file,
        # then we should also pass the same config file when signing.
        # This ensure that the requested SANs are included in the signed
        # certificate.
        if cert.csr_conf_file:
            # TODO: perhaps somehow parameterize what extensions to use?
            command += ['-extfile', cert.csr_conf_file]
        if cert.dns_alt_names:
            command+= ['-extensions', 'v3_req']

        self.log.info('Signing CSR from {} with {}'.format(cert.csr_file, self))
        if not run_command(command, creates=cert.crt_file):
            raise RuntimeError('Signing CSR {} failed'.format(cert.csr_file), self)


    def verify(self, cert):
        """
        Verifies that cert was signed with this CA.

        :param cert Certificate instance to verify
        :return boolean
        """
        # Verify that this CA was used to sign cert.crt_file.
        command = [
            openssl,
            'verify',
            '-CAfile', self.ca_cert.crt_file,
            cert.crt_file
        ]
        return run_command(command)


    def generate(self, force=False):
        """
        Generates this CA's key and certificate files by calling ca_cert.genearte().

        :param force    If true, files will be re-generated even if they already exist.
        """
        self.log.info('Generating CA certificate')
        return self.ca_cert.generate(force=force)

    def __repr__(self):
        return '{}(key_file={}, crt_file={})'.format(
            self.__class__.__name__, self.ca_cert.key.key_file, self.ca_cert.crt_file
        )


class PuppetCA(CA):
    """
    A PuppetCA signs and generates a new Certificate using the Puppet CA HTTP API and CLI.
    It does this by shelling out to a custom ruby script that imports and extends
    Puppet internals to support wildcard certificates.  This CA cannot be generated, as
    it requires an already configured Puppet CA.  This class can only be used on
    the same node where the Puppet CA lives, as it will attempt to copy the certificate file
    that Puppet CA generates into cert.crt_file.

    :param puppet_hostname      HTTP hostname for Puppet API
    :param puppet_port          HTTP port for Puppet API
    :param puppet_ca_path       Path where Puppet CA stores its certificate files.
    :param puppet_sign_script   Path of custom ruby script to use for signing certificates with Puppet CA
    """
    def __init__(
            self,
            puppet_hostname='puppet',
            puppet_port=8140,
            puppet_ca_path='/var/lib/puppet/server/ssl/ca',
            puppet_sign_script='/usr/local/bin/puppet-sign-cert',
            **kwargs
        ):

        self.name = '{}:{}'.format(puppet_hostname, puppet_port)
        self.log = get_class_logger(self)

        self.puppet_hostname = puppet_hostname
        self.puppet_port = puppet_port
        self.puppet_ca_path = puppet_ca_path
        self.puppet_sign_script = puppet_sign_script

        # Instantiate a ca_cert that will be used when a cert
        # needs to reference its CA certificate.  This is needed
        # by Certificates where ca is a PuppetCA in order to
        # generate p12 and jks files that include the Puppet CA certificate.
        self.ca_cert = Certificate(
            self.name,
            self.puppet_ca_path,
            # Dummy password and subject.
            password=None,
            subject={},
            # read_only = True ensures that no accidental call
            # to generate() on this CA cert will ever run.
            read_only = True
        )
        # Puppet CA stores certs with different filenames than our Certificate convention,
        # so set them to what they should be.
        # TODO: we could do this by create a PuppetCACertificate subclass of Certificate.  Hm.
        self.ca_cert.key_file = os.path.join(self.puppet_ca_path, 'ca_key.pem')
        self.ca_cert.crt_file = os.path.join(self.puppet_ca_path, 'ca_crt.pem')


    def sign(self, cert):
        """
        Signs a Certificate instance using Puppet CA. The generated signed certificate file
        will be copied out of puppet_cert_path to cert.crt_file.  This requires
        that cert.csr_file has been generated and exists, as it will be used when
        signing the new certificate.

        :param cert Certificate instance
        """
        #  TODO verify that cert.crt_file exists

        # call out to puppet_sign_cert.rb and then copy file from puppetmaster dirs into base_path
        command = [
            self.puppet_sign_script,
            '-H', self.puppet_hostname,
            '-P', str(self.puppet_port),
            cert.csr_file
        ]
        self.log.info('Submitting CSR {} to Puppet CA'.format(cert.csr_file))

        if not run_command(command):
            raise RuntimeError('Signing CSR {} with Puppet CA failed'.format(cert.csr_file), self)


        # Path to the signed certificate file that puppet will generate.
        puppet_crt_file = os.path.join(self.puppet_cert_path, 'signed', '{}.pem'.format(cert.name))
        if not os.path.exists(puppet_crt_file):
            raise RuntimeError(
                'Signing CSR {} with Puppet CA succeeded, but {} does not exist. '
                'This should not happen.'.format(cert.csr_file, puppet_crt_file),
                self
            )

        # COPY new puppet .crt (.pem) file into crt_file location
        mkdirs(cert.path)
        self.log.info('Copying signed certificate from {} to {}'.format(
            puppet_crt_file, cert.crt_file
        ))
        shutil.copyfile(puppet_crt_file, cert.crt_file)
        if not os.path.exists(cert.crt_file):
            raise RuntimeError(
                'Copying signed certificate from {} to {} failed'.format(
                    cert.csr_file, puppet_crt_file
                ),
                self
            )
