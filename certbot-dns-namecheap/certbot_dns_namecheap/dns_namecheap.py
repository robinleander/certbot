"""DNS Authenticator for Namecheap."""
import logging
import re

import namecheap
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://ap.www.namecheap.com/settings/tools/apiaccess/'


def _remove_suffix(s, suffix):
    if s.endswith(suffix):
        idx = s.rfind(suffix)
        return s[:idx]
    return s


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Namecheap

    This Authenticator uses the Namecheap API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Namecheap for '
                   'DNS).')
    ttl = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Namecheap credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Namecheap API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Namecheap credentials INI file',
            {
                'username': 'Username associated with Namecheap account',
                'api-key': 'API key for Namecheap account, obtained from {}'.format(ACCOUNT_URL),
                'ip-address': 'Whitelisted IP of the invoking host'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_namecheap_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_namecheap_client().del_txt_record(domain, validation_name, validation)

    def _get_namecheap_client(self):
        return _NamecheapClient(
            self.credentials.conf('username'),
            self.credentials.conf('api-key'),
            self.credentials.conf('ip-address')
        )


class _NamecheapClient(object):
    """
    Encapsulates all communication with the Namecheap API.
    """

    def __init__(self, username, api_key, ip_address):
        self.nc = namecheap.Api(username, api_key, username, ip_address, sandbox=False)

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Namecheap zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Namecheap API
        """

        record = {'Type': 'TXT',
                  'Name': _remove_suffix(record_name, domain),
                  'Address': record_content,
                  'TTL': record_ttl}

        try:
            logger.debug('Attempting to add record: %s', record)
            self.nc.domains_dns_addHost(domain, record)
        except namecheap.ApiError as e:
            logger.error('Encountered NamecheapAPIError adding TXT record: %d %s', e, e)
            raise errors.PluginError('Error communicating with the Namecheap API: {0}'.format(e))

        logger.debug('Successfully added TXT record')

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Namecheap zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        record = {'Type': 'TXT',
                  'Name': _remove_suffix(record_name, domain),
                  'Address': record_content}
        try:
            logger.debug('Attempting to add record: %s', record)
            self.nc.domains_dns_delHost(domain, record)
        except namecheap.ApiError as e:
            logger.error('Encountered NamecheapAPIError deleting TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Namecheap API: {}'.format(e))

        logger.debug('Successfully removed TXT record')
