#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import os.path
import subprocess
import tempfile
import yaml    # PyYAML (python-yaml)

from .ca import *

openssl = os.getenv('OPENSSL_BIN', 'openssl')
keytool = os.getenv('KEYTOOL_BIN', 'keytool')

__all__ = (
    'setup_logging', 'get_class_logger', 'run_command', 'mkdirs', 'is_in_keystore'
)


def setup_logging(level=None):
    """
    Conigures basic logging defaults.
    If level is not given, but the environment variable LOG_LEVEL
    is set, it will be used as the level.  Otherwise INFO is the default level.

    :param level
    """
    if not level:
        level = getattr(
            logging, os.environ.get('LOG_LEVEL', 'INFO')
        )

    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-8s %(name)-22s %(message)s'
    )

# TODO don't call this from file
setup_logging()



def get_class_logger(obj):
    """
    Returns a new logging instance for an class object instance.
    If the obj instance has a name attribute, it will be included
    in the logger name.  This is useful for using %(name)s in
    logging your formatter.

    :param obj an instance of any class
    """
    class_name = obj.__class__.__name__
    if hasattr(obj, 'name'):
        logger_name = '{}({})'.format(class_name, obj.name)
    else:
        logger_name = class_name
    return logging.getLogger(logger_name)


def run_command(command, creates=None):
    """
    Executes a command in a subshell and logs the output.

    :param command a list of command args to pass to subprocess.check_output
    :return True if the command exited with 0, else False
    """
    logger = logging.getLogger('shell')

    if isinstance(command, str):
        command = command.split()
    try:
        logger.debug("Running command: " + " ".join(command))
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        for ln in output.splitlines(): logger.debug(ln)

        # Ensure that any files that this command should have created exist.
        if creates:
            if isinstance(creates, str):
                creates = [creates]
            for f in creates:
                if not os.path.exists(f):
                    logger.error(
                        'command succeeded, but was expected to create file {} '
                        'and it does not exist. command: {}'.format(f, ' '.join(command))
                    )
                    return False

    except subprocess.CalledProcessError as e:
        for ln in e.output.splitlines(): logging.error(ln)
        logger.error("command returned status %d: %s", e.returncode, " ".join(command))
        return False


    logger.debug("command succeeded: %s", " ".join(command))
    return True


def mkdirs(directory):
    """
    Equivalent to mkdir -p

    :param directory path
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

def is_in_keystore(alias, jks_file, password):
    command = [
        keytool,
        '-list',
        '-alias', alias,
        '-storepass', password,
        '-keystore', jks_file
    ]
    return run_command(command)
