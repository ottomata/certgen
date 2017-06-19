# certpy

Manages and generates OpenSSL key and certificate files declared in a YAML manifest.

Generation of the following file types is currently supported:

- ```.key``` - OpenSSL private key in .pem format.
- ```.crt``` - OpenSSL public key certificate in .pem format
- ```.p12``` - PKCS#12 key store file.
- ```.jks``` - Java keystore file.

## Usage

```
certpy -h
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
    -A --generate-authorities   Generate all CA certficiate files, if possible.
    -F --force                  If given a generate option without --force, any existing files will not
                                be overwritten.  If want to overwrite files, provide --force.
    -v --verbose                Turn on verbose debug logging.

```

certpy's CLI works with a YAML manifest.  The manifest declares various certificate and key
parameters that are then used to instantiate model classes that can generate key and
certificate files.


### certpy manifest .yaml

The manifest yaml attempts to match the kwargs that can be used to instantiate
various model classes.  This allows new model subclasses to be created and
instantiated with manfiest configuration without having to write code to
handle the config -> code instantiation.

A manifest can declare 2 top level configration keys, ```authorities``` and ```certs```

#### ```certs```

The ```certs``` config object should be a hash of certificate common names to
certificate parameters.

```
certs:
  # Common name of the certificate
  hostname1.example.org:
    # Directory where OpenSSL files will live
    path: certificates/hostname1.example.org
    # Name of the CA to use for this certificate.  This must match
    # A name of an authority in the authorities manifest. (optional)
    ca: rootCa
    # x509 subject
    subject:
      C: US
    # DNS alternate names to put in the SAN (optional)
    dns_alt_names: [example.org]
    # Password to use for keystore files.
    password: qwerty
    # Key class configuration
    key:
      # Fully qualified (with module name if needed) class name to use for the key.
      type: ECKey
      # Private key password.  Optional.  If not provided,
      # the certificate's keystore password will be used.
      password: qwerty

  hostname2.example.org
    ...
````

#### ```authorities```

The ```authorities``` config object should be a hash of CA names to CA and CA certificate
parameters.

```
authorities:
  # The name of this CA.  This will be used as the CA cert's common name.
  rootCa:
    # Fully qualified (with module name if needed) class name to use for the CA class.
    # If not given, SelfSigningCA will be used. (TODO)
    type: SelfSigningCA
    # A Certificate config object, with the same structure used to declare certs in
    # the certificates config object.
    cert:
      path: .certificates/rootCa
      subject:
        C: US
      password: qwerty
      key:
        type: RSAKey
        password: qwerty
  #TODO: document and test PuppetCA.
  puppet:
    type: PuppetCA
```

Note that some authorities here may not be generateable, and as such will not need to declare
the specifics of the CA certs.

## certpy as module
certpy can be used as a python library to model OpenSSL Keys, Certificates and CAs.  The
underlying code does not depend on a Python implementation of OpenSSL, but instead
shells out to the openssl CLI and the Java keytool CLI in order to generate and verify
certificate files in different formats.

There are 3 top level models:

### ```Key```
A ```Key``` class represents an OpenSSL private key.  See docuemntation for ```certpy.key```
for more information and instructions on how to implement more ```Key``` subclasses.

Currently this package provides an ```RSAKey``` and an ```ECKey``` (elliptic curve) ```Key``` implementations.

### ```Certificate```
A ```Certificate``` class represents OpenSSL certificate and files.  It is used to ensure that
supported file formats exist, and to generate them if they don't.  ```Certificate```
is not meant to be subclassed.

### ```CA```
A ``CA`` class is an implementation of a Certificate Authority.  It is meant to wrap the
``Certificate`` class, as often a ``CA`` has it's own key and certificate files.  However, the
main purpose is to provide an interface for ```Certificate```s to generate CSR
(Certificate Signing Requests) and have a CA sign and generate a signed public ```.crt```
file.  It is not necessary for ```CA``` subclasses to be given a ````Certfificate```` instance,
but they will need to at least instantiate a ```self.ca_cert``` ```Certificate``` instance
themselves, even with dummy values, so that logging and status reporting of certificate file existance works.

Every ```CA``` subclass should implement the ```sign``` and ```verify``` methods, and if possible,
a ```generate``` method.

Currently this package provides a ```SelfSigningCA``` and ```PuppetCA``` implementations.

#### ```SelfSigningCa```
This ```CA``` uses its own Certificate instance to signing other Certificate files.

#### ```PuppetCA```
This ```CA``` uses a puppet master CA instance to sign CSRs and generate ```.crt``` files.
Because Puppet manages its own certificate files, usage of this ```CA``` must be done on the
same node as the puppet master CA, so that it can copy the Puppet generated ```.crt.pem``` file
out of the Puppet CA paths into the ```Certificate```'s expected ```.crt``` file path.

