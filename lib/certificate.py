# -*- coding: utf-8 -*-

import os
import logging
import tempfile

from .key import RSAKey
from .util import openssl, keytool, run_command, mkdirs, get_class_logger


subject_fields = ['C', 'ST', 'O', 'OU', 'DN', 'CN', 'L', 'SN', 'GN']

class SubjectKeyError(KeyError):
    def __init__(self, key):
        super().__init__('{} is not a valid x509 subject field, must be one of {}'.format(
            key, ', '.join(subject_fields)
        ))

# TODO: support long names?  mehhhhhh. use named tuple?? or UserDict
class Subject(dict):
    def factory(d):
        subject_dict = {k.upper(): v for k,v in d.items()}
        for k in subject_dict.keys():
            if k not in subject_fields:
                raise SubjectKeyError(k)

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



csr_config_template = """
[ req ]
distinguished_name         = req_distinguished_name
{req_extensions}

[ req_distinguished_name ]
countryName                = Country Name (2 letter code)
stateOrProvinceName        = State or Province Name (full name)
localityName               = Locality Name (eg, city)
organizationName           = Organization Name (eg, company)
commonName                 = Common Name (e.g. server FQDN or YOUR name)
"""

san_config_template = """
[ v3_req ]
subjectAltName             = @alt_names

[ alt_names ]
{alt_names}
"""

dns_alt_name_template = 'DNS.{i} = {alt_name}'

# def generate_temp_san_conf_file(dns_alt_names):
#     san_file = tempfile.NamedTemporaryFile(mode='w')
#     san_file.write('subjectAltName=DNS:{}'.format(',DNS:'.join(dns_alt_names)))
#     san_file.flush()
#     return san_file


def render_csr_config(dns_alt_names=None):
    req_extensions = ''
    alt_names = ''
    if dns_alt_names:
        req_extensions = 'req_extensions             = v3_req'
        for i, name in enumerate(dns_alt_names):
            alt_names += dns_alt_name_template.format(i=i+1, alt_name=name) + '\n'

    content = csr_config_template.format(req_extensions=req_extensions)
    if dns_alt_names:
        content += san_config_template.format(alt_names=alt_names)

    return content




class Certificate(object):
    """
    docstring for Certificate.
    subject is a dict mapping x509 subject  keys to values.
    """
    def __init__(
        self,
        name,
        path,
        password,
        key=None,
        subject=default_subject,
        dns_alt_names=None,
        expiry_days=None,
        digest=None,
        ca=None,
        read_only=False
    ):
        self.name = name
        self.path = os.path.abspath(path)
        self.key = key

        subject['CN'] = name # TODO: ???
        self.subject = Subject.factory(subject)
        self.dns_alt_names = dns_alt_names

        self.expiry_days = expiry_days
        self.password = password

        # TODO validate that digest is supported (e.g. sha256)
        self.digest = digest

        # TODO Validate that ca is instanceof CA
        self.ca = ca

        self.read_only = read_only

        # If not give a key, then create a new RSA key by default.  TODO: keep this?
        if key:
            self.key = key
        else:
            self.key = RSAKey(name, path, password)

        # Private Key in .pem format
        self.key_file = self.key.key_file
        # Certificate Signing Request
        self.csr_file = os.path.join(self.path, '{}.csr'.format(self.name))
        # CSR config file.  Needed to support SANs.
        self.csr_conf_file = os.path.join(self.path, '{}.csr.cnf'.format(self.name))
        # Public Signed Certificate in .pem format
        self.crt_file = os.path.join(self.path, '{}.crt'.format(self.name))

        # PKCS#12 'keystore' file
        self.p12_file = os.path.join(self.path, '{}.p12'.format(self.name))
        # Java Keystore
        self.jks_file = os.path.join(self.path, '{}.jks'.format(self.name))

        self.log = get_class_logger(self)

    def should_generate(self, path, force):
        if os.path.exists(path) and not force:
            self.log.warn(
                '{} exists, skipping generation...'.format(path)
            )
            return False
        else:
            return True

    def generate(self, force=False):
        if self.read_only:
            raise RuntimeError('Cannot call generate on a read_only Certificate', self)
        mkdirs(self.path)
        self.key.generate(force=force)
        self.generate_crt(force=force)
        self.generate_p12(force=force)
        self.generate_keystore(force=force)

    def generate_crt(self, force=False):
        if not self.should_generate(self.crt_file, force):
            return # TODO return what?

        # If we are going to include DNS alt names in the cert,
        # we'll need a CSR conf file that specifies them.  For consistency,
        # generate this conf file even if there are no DNS alt names specified.
        self._generate_csr_conf()

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
            '-config', self.csr_conf_file,
            '-subj', self.subject.openssl_string(),
            '-key', self.key.key_file,
            '-out', self.crt_file
        ]
        if self.digest:
            command += ['-{}'.format(self.digest)]
        if self.expiry_days:
            command =+ ['-days', str(self.expiry_days)]
        if self.key.password:
            command += ['-passin', 'pass:{}'.format(self.key.password)]
        # If we need to instruct the x509 cert to use our custom SAN
        # extensions section in the conf file.
        if self.dns_alt_names:
            command += ['-extensions', 'v3_req']

        self.log.info('Generating self signed certificate')
        if not run_command(command):
            raise RuntimeError('Certificate generation failed', self)
        # TODO verify that self.crt_file now exists


    def _ca_generate_crt(self):
        self.log.info('Sending CSR to {}'.format(self.ca))

        self.generate_csr()
        self.ca.sign(self)

        self.log.info('Verifying signed certificate with {}'.format(self.ca))
        self.ca.verify(self.crt_file)


    def _generate_csr_conf(self):
        csr_config_content = render_csr_config(self.dns_alt_names)
        with open(self.csr_conf_file, 'w') as f:
            f.write(csr_config_content)
            f.flush()
        # TODO verify that that csr_conf_file is generated


    def generate_csr(self):
        # In order to support adding SANs to the CSR,
        # we need to use a config file.  To be consistent, we generate
        # and use this config file, event if we don't have any SANS
        self._generate_csr_conf()

        command = [
            openssl,
            'req',
            '-new',
            '-config', self.csr_conf_file,
            '-subj', self.subject.openssl_string(),
            '-key', self.key.key_file,
            '-out', self.csr_file
        ]
        if self.digest:
            command += ['-{}'.format(self.digest)]
        if self.key.password:
            command += ['-passin', 'pass:{}'.format(self.key.password)]

        self.log.info('Generating CSR')
        if not run_command(command):
            raise RuntimeError('CSR generation failed', self)
        # TODO check that csr_file exists


    def generate_p12(self, force=False):
        if not self.should_generate(self.p12_file, force):
            return # TODO return what?

        command = [
            openssl,
            'pkcs12',
            '-export',
            '-name', self.name,
            # private key
            '-inkey', self.key.key_file,
            #  Public certificate
            '-in', self.crt_file,
            # output p12 keystore with password
            '-passout', 'pass:{}'.format(self.password),
            '-out', self.p12_file,
        ]
        if self.key.password:
            command += ['-passin', 'pass:{}'.format(self.key.password)]

        if self.ca:
            command += ['-CAfile', self.ca.ca_crt.crt_file]

        self.log.info('Generating PKCS12 keystore')
        if not run_command(command):
            raise RuntimeError('PKCS12 file generation failed', self)
        # TODO check that p12 file exists

    def generate_keystore(self, force=False):
        if not self.should_generate(self.jks_file, force):
            return # TODO return what?

        command = [
            keytool,
            '-importkeystore',
            '-noprompt',
            '-alias', self.name,
            '-srcstoretype', 'PKCS12',
            '-srcstorepass', self.password,
            '-srckeystore', self.p12_file,
            '-deststorepass', self.password,
            '-destkeystore', self.jks_file
        ]
        if self.key.password:
            command += ['-srckeypass', self.key.password, '-destkeypass', self.key.password]

        self.log.info('Generating Java keystore')
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
                '-storepass', self.password,
                '-keystore', self.jks_file
            ]
            self.log.info('Importing CA cert {} into Java keystore'.format(self.ca))
            if not run_command(command):
                raise RuntimeError('Import of CA certificate into Java Keystore failed', self)
            # TODO check that jks file exists and has CA cert

    def __repr__(self):
        return '{}(name={}, file={}, subject={}, key={}, ca={})'.format(
            self.__class__.__name__, self.name, self.crt_file,
            self.subject.openssl_string(), self.key.key_file, self.ca.name
        )
