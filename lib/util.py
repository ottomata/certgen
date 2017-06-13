#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import os.path
import subprocess
import tempfile
import yaml    # PyYAML (python-yaml)



openssl = os.getenv('OPENSSL_BIN', 'openssl')
keytool = os.getenv('KEYTOOL_BIN', 'keytool')


def setup_logging(level=logging.DEBUG):
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(name)-20s %(message)s'
    )

setup_logging()


def get_class_logger(obj):
    return logging.getLogger('{}({})'.format(
        obj.__class__.__name__, obj.name
    ))

def read_manifest(manifest):
    with open(manifest, 'r') as f:
        return yaml.load(f.read())

def run_command(command):
    logger = logging.getLogger('shell')

    if isinstance(command, str):
        command = command.split()
    try:
        logger.debug("Running command: " + " ".join(command))
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        for ln in output.splitlines(): logger.debug(ln)
        logger.debug("command succeeded: %s", " ".join(command))
    except subprocess.CalledProcessError as e:
        for ln in e.output.splitlines(): logging.error(ln)
        logger.error("command returned status %d: %s", e.returncode, " ".join(command))
        return False
    return True


def mkdirs(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
