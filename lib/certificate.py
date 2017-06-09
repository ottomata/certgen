# -*- coding: utf-8 -*-

import os
import logging

from .key import RSAKey
from .util import openssl, keytool, run_command, mkdirs


subject_fields = ['C', 'ST', 'O', 'OU', 'DN', 'CN', 'L', 'SN', 'GN']

class SubjectKeyError(KeyError):
    def __init__(self, key):
        super().__init__('{} is not a valid x509 subject field, must be one of {}'.format(
            key, ', '.join(subject_fields)
        ))

class Subject(dict):
    def factory(d):
        subject_dict = {k.upper(): v for k,v in d.items()}
        for k in subject_dict.keys():
            if k not in subject_fields:
                raise SubjectKeyError(k)

        # [raise SubjectKeyError(k) if k not in subject_fields for k in subject_dict.keys()]
        return Subject(subject_dict)

    def openssl_string(self):
        a = ['{}={}'.format(k.upper(), v) for k, v in self.items()]
        return '/' + '/'.join(a) + '/'

    def keytool_string(self):
        a = ['{}={}'.format(k.lower(), v) for k, v in self.items()]
        return ', '.join(a)



# TODO: remove
default_subject = Subject.factory({
    'O': 'WMF',
    'C': 'US',
})


def should_generate(path, force):
    if os.path.exists(path) and not force:
        logging.warn(
            '{} exists, skipping generation...'.format(path)
        )
        return False
    else:
        return True


class Certificate(object):
    """
    docstring for Certificate.
    subject is a dict mapping x509 subject  keys to values.
    """
    def __init__(self, name, path, key=None, subject=default_subject, expiry_days=None, password=None, ca=None):
        self.name = name
        self.path = os.path.abspath(path)
        self.key = key

        subject['CN'] = name
        self.subject = Subject.factory(subject)

        self.expiry_days = expiry_days
        self.password = password
        # TODO Validate that ca is instanceof CA
        self.ca = ca

        # If not give a key, then create a new RSA key by default.  TODO: keep this?
        if key:
            self.key = key
        else:
            self.key = RSAKey(name, path, password)

        # Private Key in .pem format
        self.key_file = self.key.key_file
        # Certificate Signing Request
        self.csr_file = os.path.join(self.path, '%s.csr' % self.name)
        # Public Signed Certificate in .pem format
        self.crt_file = os.path.join(self.path, '%s.crt' % self.name)

        # PKCS#12 'keystore' file
        self.p12_file = os.path.join(self.path, '%s.p12' % self.name)
        # Java Keystore
        self.jks_file = os.path.join(self.path, '%s.jks' % self.name)

    def generate(self, force=False):
        mkdirs(self.path)
        self.key.generate(force=force)
        self.generate_crt(force=force)
        self.generate_p12(force=force)
        self.generate_keystore(force=force)

    def generate_crt(self, force=False):
        if not should_generate(self.crt_file, force):
            return # TODO return what?

        # If no ca was provided, then generate a self signed certificate
        if not self.ca:
            self._self_generate_crt()
        else:
            self._ca_generate_crt()


    def _self_generate_crt(self):
        # Generate the certificate without a ca
        command = [
            openssl,
            'req',
            '-x509',
            '-new',
            '-nodes',
            '-subj', self.subject.openssl_string(),
            '-key', self.key.key_file,
            '-out', self.crt_file
        ]
        if self.expiry_days:
            command =+ ['-days', str(self.expiry_days)]

        if not run_command(command):
            raise RuntimeError('Certificate generation failed', self)
        # TODO verify that self.crt_file now exists



    def _ca_generate_crt(self):
        # generate the CSR:
        self.generate_csr()
        self.ca.sign(self.csr_file, self.crt_file)
        self.ca.verify(self.crt_file)



    def generate_csr(self):
        command = [
            openssl,
            'req',
            '-new',
            '-sha256',
            '-nodes',
            '-subj', self.subject.openssl_string(),
            '-key', self.key.key_file,
            '-out', self.csr_file
        ]
        if self.key.password:
            command += ['-passin', 'pass:{}'.format(self.key.password)]

        if not run_command(command):
            raise RuntimeError('CSR generation failed', self)
        # TODO check that csr_file exists


    def sign(self):
        # TODO generate csr?
        if self.ca:
            self.ca.sign(self.csr_file)
        else:
            # TODO: proper error
            raise RuntimeError(' NO CA')
        # TOD: check that self.crt_file is created?

    def generate_p12(self, force=False):
        if not should_generate(self.p12_file, force):
            return # TODO return what?

        command = [
            openssl,
            'pkcs12',
            '-export',
            '-name', self.name,
            # private key and password
            '-inkey', self.key.key_file,
            #  Public certificate
            '-in', self.crt_file,
            # output p12 keystore and password
            '-out', self.p12_file
            # Have to always -passout to bypass interactive.
            # '-passout', 'pass:{}'.format(self.password or ''),
        ]
        if self.key.password:
            command += ['-passin', 'pass:{}'.format(self.key.password)]
        if self.password:
            command += ['-passout', 'pass:{}'.format(self.password)]

        if self.ca:
            command += ['-CAfile', self.ca.ca_crt.crt_file]
        if not run_command(command):
            raise RuntimeError('PKCS12 file generation failed', self)
        # TODO check that p12 file exists

    def generate_keystore(self, force=False):
        if not should_generate(self.jks_file, force):
            return # TODO return what?

        command = [
            keytool,
            '-importkeystore',
            '-noprompt',
            '-alias', self.name,
            '-srcstoretype', 'PKCS12',
            '-srckeystore', self.p12_file,
            '-destkeystore', self.jks_file,
        ]
        if self.key.password:
            command += ['-srckeypass', self.key.password, '-destkeypass', self.key.password]
        if self.password:
            command += ['-srcstorepass', self.password, '-deststorepass', self.password]

        if not run_command(command):
            raise RuntimeError('Java Keystore generation and import of certificate failed', self)
        # TODO check that jks file exists and has cert

        # If this certificate was signed by a CA, then also
        # import the CA certificate into the keystore.
        if self.ca:
            command = [
                keytool,
                '-importcert',
                '-noprompt',
                "-alias",     self.ca.ca_crt.name,
                '-file', self.ca.ca_crt.crt_file,
                '-keystore', self.jks_file
            ]
        if self.password:
            command += ['-storepass', self.password]

            if not run_command(command):
                raise RuntimeError('Import of CA certificate into Java Keystore failed', self)
            # TODO check that jks file exists and has CA cert

    def __repr__(self):
        return '{}(name={}, file={}, subject={}, expiry_days={})'.format(
            self.__class__.__name__, self.name, self.crt_file,
            self.subject.openssl_string(), self.expiry_days
        )
