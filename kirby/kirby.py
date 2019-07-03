#!/usr/bin/python3
"""Author:      Olivier van der Toorn <o.i.vandertoorn@utwente.nl>
Description:    Initializes a Kerberos ticket, through the Kirby class.
"""
import subprocess
import getpass
import os
import logging
import re
import datetime


# pylint: disable=too-few-public-methods
class Kirby():
    """Runs the kinit command for you using the correct username and keytab.
    """
    user = None
    keytab = None

    def __init__(self, user=None, keytab=None):
        """Sets up a kerberos ticket.
        """
        logging.basicConfig(
            format=('%(asctime)s - %(funcName)20s'
                    '- %(levelname)-8s - %(message)s'),
            level='DEBUG')
        if user is not None:
            self.user = user

        if keytab is not None:
            self.keytab = keytab

        with open(
                os.path.join(os.path.expanduser('~'), '.kirby'),
                'r') as kirby_file:
            self.url = kirby_file.read().replace('\n', '')

        if check(self.url) is True:
            logging.info("Kerberos ticket is still valid")
            return

        logging.info("Performing Kerberos authentication for OpenINTEL ... ")
        self.user = getpass.getuser()
        self.keytab = find_keytab()
        if self.kinit() is True:
            logging.info("OK")

        else:
            logging.info("FAILED")

    def kinit(self):
        """Makes sure the Kerberos ticket is valid.
        """
        if self.user is None and self.keytab is None:
            raise RuntimeError('no user and/or keytab specified')

        connection = "{0}@{1}".format(self.user, self.url.upper())
        command = ['kinit', '-k', '-t', self.keytab, connection]
        logging.debug('running command: %s', " ".join(command))
        try:
            return_code = subprocess.check_call(command)

        except subprocess.CalledProcessError as error:
            logging.error(error)
            return_code = -1

        if return_code == 0:
            return True

        return False


def find_keytab():
    """Finds the keytab in the users home directory.

    :return: path to the keytab
    """
    path = None
    homedir = os.path.expanduser('~')
    for item in os.listdir(homedir):
        if item.endswith('.keytab'):
            path = os.path.join(homedir, item)
            logging.info('found keytab: %s', path)
            break

    return path


def check(url):
    """Checks for a valid kerberos ticket.

    :return: boolean for validity
    """
    valid = False
    command = ['klist']
    try:
        output = subprocess.check_output(command)

    except subprocess.CalledProcessError as error:
        logging.error(error)
        return False

    output_lines = str(output, 'utf-8')
    ticket = re.search((r'([0-9]{2}/[0-9]{2}/[0-9]{2}\s'
                        r'[0-9]{2}:[0-9]{2}:[0-9]{2})\s+'
                        r'([0-9]{2}/[0-9]{2}/[0-9]{2}\s'
                        r'[0-9]{2}:[0-9]{2}:[0-9]{2}).*%s') % url,
                       output_lines)
    if ticket:
        expire = datetime.datetime.strptime(
            ticket.group(2), '%m/%d/%y %H:%M:%S')
        now = datetime.datetime.now() + datetime.timedelta(seconds=60)
        if now < expire:
            valid = True

    return valid


if __name__ == '__main__':
    Kirby()
