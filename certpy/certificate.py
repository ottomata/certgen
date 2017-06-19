# -*- coding: utf-8 -*-

from datetime import datetime
import os
import logging
import shutil

from .key import RSAKey
from .util import openssl, keytool, run_command, mkdirs, get_class_logger, is_in_keystore

subject_fields = ['C', 'ST', 'O', 'OU', 'DN', 'CN', 'L', 'SN', 'GN']

__all__ = ('Certificate', 'Subject', 'SubjectKeyError')


class SubjectKeyError(KeyError):
    def __init__(self, key):
        super().__init__('{} is not a valid x509 subject field, must be one of {}'.format(
            key, ', '.join(subject_fields)
        ))

# TODO: support long names?  mehhhhhh. use named tuple?? or UserDict
class Subject(dict):
    @staticmethod
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
    Represents an OpenSSL certificate.  Handles generation of
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

        # Verify that CA has required methods. ( duck typing :) )
        if ca and (
            not hasattr(ca, 'sign') or
            not hasattr(ca, 'verify')
            ):
            raise RuntimeError(
                'Cannot instante new Certificate. ca {} should implement '
                'both sign and verify methods.'.format(ca),
                self
            )

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

    # TODO: rename this since we are removing paths, and clean up conditional logic.
    def should_generate(self, path=None, force=False):
        should_generate = True
        if self.read_only:
            self.log.warn(
                'Cannot call any generate method on a read_only Certificate.  Skipping generation.'
            )
            should_generate = False
        elif path and os.path.exists(path):
            if force:
                self.log.warn(
                    '{} exists, but force is True.  Removing before '
                    'continuing with generation.'.format(path)
                )
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                should_generate = True
            else:
                self.log.warn(
                    '{} exists, skipping generation.'.format(path)
                )
                should_generate = False
        else:
            should_generate = True

        return should_generate

    def generate(self, force=False):
        # This top level should_generate check looks for the existence of self.path.
        # It will not even attempt to recreate the files if self.path exists and force=False.
        if not self.should_generate(self.path, force):
            return False

        self.log.info('Generating all files...')
        mkdirs(self.path)

        self.key.generate(force=force)
        self.generate_crt(force=force)
        self.generate_p12(force=force)
        self.generate_keystore(force=force)

        return True

    def generate_crt(self, force=False):
        if not self.should_generate(self.crt_file, force):
            return False

        # If we are going to include DNS alt names in the cert,
        # we'll need a CSR conf file that specifies them.  For consistency,
        # generate this conf file even if there are no DNS alt names specified.
        self._generate_csr_conf(force=force)

        # If no ca was provided, then generate a self signed certificate
        if not self.ca:
            self._self_generate_crt(force=force)
        else:
            self._ca_generate_crt(force=force)


    def _self_generate_crt(self, force=False):
        if not self.should_generate(self.crt_file, force):
            return False

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
        if not run_command(command, creates=self.crt_file):
            raise RuntimeError('Certificate generation failed', self)

        return True

    def _ca_generate_crt(self, force=False):
        if not self.should_generate(self.crt_file, force):
            return False

        self.generate_csr(force=force)
        self.log.info('Sending CSR to {}'.format(self.ca))
        self.ca.sign(self)

        # Verify that crt_file was created by the CA when it signed CSR.
        if not os.path.exists(self.crt_file):
            raise RuntimeError(
                '{} does not exist even though {} signed and generated a '
                'certificate.  This should not happen'.format(self.crt_file, self.ca)
            )

        self.log.info('Verifying signed certificate with {}'.format(self.ca))
        if not self.ca.verify(self):
            raise RuntimeError('Certificate {} verification failed with {}'.format(
                self.crt_file, self.ca
            ))

        return True

    def generate_csr(self, force=False):
        if not self.should_generate(self.csr_file, force):
            return False

        # In order to support adding SANs to the CSR,
        # we need to use a config file.  To be consistent, we generate
        # and use this config file, event if we don't have any SANS
        self._generate_csr_conf(force=force)

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
        if not run_command(command, creates=self.csr_file):
            raise RuntimeError('CSR generation failed', self)

        return True

    def _generate_csr_conf(self, force=False):
        if not self.should_generate(self.csr_conf_file, force):
            return False

        csr_config_content = render_csr_config(self.dns_alt_names)
        with open(self.csr_conf_file, 'w') as f:
            f.write(csr_config_content)
            f.flush()
        if not os.path.exists(self.csr_conf_file):
            raise RuntimeError(
                'Attempted to write CSR conf file {}, but it does not exist. '
                'This should not happen.'.format(self.csr_conf_file),
                self
            )
        return True


    def generate_p12(self, force=False):
        if not self.should_generate(self.p12_file, force):
            return False

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
            #  TODO: This will not work with PuppetCA!
            command += ['-CAfile', self.ca.ca_cert.crt_file]

        self.log.info('Generating PKCS12 keystore')
        if not run_command(command, creates=self.p12_file):
            raise RuntimeError('PKCS12 file generation failed', self)

        # Verify that the cert is in the P12 file.
        if not is_in_keystore(self.name, self.p12_file, self.password):
            raise RuntimeError(
                'Generation of PKS12 keystore succeeded, but a key for '
                '{} is not in {}. This should not happen'.format(
                    self.name, self.jks_file
                )
            )

        # TODO: do we need to import the ca_cert into the PKS12 keystore too?

        return True

    def generate_keystore(self, force=False):
        if not self.should_generate(self.jks_file, force):
            return False

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
        if not run_command(command, creates=self.jks_file):
            raise RuntimeError(
                'Java Keystore generation and import of certificate failed', self
            )

        # Verify that the cert is in the Java Keystore.
        if not is_in_keystore(self.name, self.jks_file, self.password):
            raise RuntimeError(
                'Java Keystore generation and import of certificate '
                'succeeded, but a key for {} is not in {}.  This should not happen'.format(
                    self.name, self.jks_file
                )
            )

        # If this certificate was signed by a CA, then also
        # import the CA certificate into the keystore.
        if self.ca:
            command = [
                keytool,
                '-importcert',
                '-noprompt',
                "-alias",     self.ca.ca_cert.name,
                '-file', self.ca.ca_cert.crt_file,
                '-storepass', self.password,
                '-keystore', self.jks_file
            ]
            self.log.info('Importing {} cert into Java keystore'.format(self.ca))
            if not run_command(command):
                raise RuntimeError(
                    'Import of {} cert into Java Keystore failed'.format(self.ca), self
                )
            # Verify that the ca_cert is in the Java Keystore.
            if not is_in_keystore(self.ca.ca_cert.name, self.jks_file, self.password):
                raise RuntimeError(
                    'Import of {} certificate into Java Keystore succeeded, but a key for '
                    '{} is not in {}. This should not happen'.format(
                        self.ca, self.ca.cert.name, self.jks_file
                    )
                )

        return True

    def __repr__(self):
        if self.ca:
            return '{}(name={}, keytype={}, ca={})'.format(
                self.__class__.__name__, self.name,
                self.key.__class__.__name__, self.ca.name
            )
        else:
            return '{}(name={}, keytype={})'.format(
                self.__class__.__name__, self.name,
                self.key.__class__.__name__
            )


    def status_string(self):
        file_statuses = []
        for p in [self.key_file, self.crt_file, self.p12_file, self.jks_file]:
            if os.path.exists(p):
                mtime = datetime.fromtimestamp(os.path.getmtime(p)).isoformat()
                file_statuses += ['\t{}: PRESENT (mtime: {})'.format(p, mtime)]

            else:
                file_statuses += ['\t{}: ABSENT'.format(p)]

        return '{}:\n{}'.format(self, '\n'.join(file_statuses))
