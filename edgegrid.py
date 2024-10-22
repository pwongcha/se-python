import time
import uuid
import httpx
from configparser import ConfigParser
from urllib.parse import urlparse
import hashlib
import hmac
import base64
import logging
from os.path import expanduser
import os
import re
from time import gmtime, strftime



logger = logging.getLogger(__name__)


def eg_timestamp():
    return strftime('%Y%m%dT%H:%M:%S+0000', gmtime())


def new_nonce():
    return uuid.uuid4()


def base64_hmac_sha256(data, key):
    return base64.b64encode(
        hmac.new(
            key.encode('utf8'),
            data.encode('utf8'),
            hashlib.sha256).digest()
    ).decode('utf8')


class EdgeGridAuthHeaders():
    def __init__(self, client_token, client_secret, access_token, headers_to_sign=(), max_body=131072):
        self.client_token = client_token
        self.client_secret = client_secret
        self.access_token = access_token
        self.headers_to_sign = [h.lower() for h in headers_to_sign]
        self.max_body = max_body

    def make_signing_key(self, timestamp):
        signing_key = base64_hmac_sha256(timestamp, self.client_secret)
        logger.debug(f'signing_key: {signing_key}\n')
        return signing_key

    def sign_request(self, url, headers, method, body, timestamp, auth_header):
        sign_data = base64_hmac_sha256(
            self.make_data_to_sign(url, headers, auth_header, method, body),
            self.make_signing_key(timestamp)
        )
        logger.debug(f'signature:   {sign_data}\n')
        return sign_data

    def make_auth_header(self, url, headers, method, body, timestamp, nonce):
        kvps = [
            ('client_token', self.client_token),
            ('access_token', self.access_token),
            ('timestamp', timestamp),
            ('nonce', nonce),
        ]
        auth_header = "EG1-HMAC-SHA256 " + \
            ';'.join(["%s=%s" % kvp for kvp in kvps]) + ';'

        logger.debug(f'unsigned authorization header: {auth_header}\n')
        signature = self.sign_request(url, headers, method, body, timestamp, auth_header)
        signed_auth_header = f'{auth_header}signature={signature}'

        logger.debug(f"signed authorization header:   {signed_auth_header}")
        return signed_auth_header

    def make_data_to_sign(self, url, headers, auth_header, method, body):
        parsed_url = urlparse(str(url))
        if headers.get('Host', False):
            netloc = headers['Host']
        else:
            netloc = parsed_url.netloc

        self.get_header_versions(headers)

        data_to_sign = '\t'.join([
            method,
            parsed_url.scheme,
            netloc,
            # Note: relative URL constraints are handled by requests when it sets up 'r'
            parsed_url.path + (';' + parsed_url.params if parsed_url.params else "") +
            ('?' + parsed_url.query if parsed_url.query else ""),
            self.canonicalize_headers(headers),
            self.make_content_hash(body or '', method),
            auth_header
        ])
        return data_to_sign

    def canonicalize_headers(self, headers):
        spaces_re = re.compile('\\s+')
        # note: r.headers is a case-insensitive dict and self.headers_to_sign
        # should already be lowercased at this point
        return '\t'.join([
            "%s:%s" % (h, spaces_re.sub(' ', headers[h].strip()))
            for h in self.headers_to_sign if h in headers
        ])

    def make_content_hash(self, body, method):
        content_hash = ""
        if method == 'POST' and body:
            content_hash = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        return content_hash

    def get_header_versions(self, header=None):
        if header is None:
            header = {}

        version_header = ''
        akamai_cli = os.getenv('AKAMAI_CLI')
        akamai_cli_version = os.getenv('AKAMAI_CLI_VERSION')
        if akamai_cli and akamai_cli_version:
            version_header += " AkamaiCLI/" + akamai_cli_version

        akamai_cli_command = os.getenv('AKAMAI_CLI_COMMAND')
        akamai_cli_command_version = os.getenv('AKAMAI_CLI_COMMAND_VERSION')
        if akamai_cli_command and akamai_cli_command_version:
            version_header += " AkamaiCLI-" + akamai_cli_command + \
                "/" + akamai_cli_command_version

        if version_header != '':
            if 'User-Agent' not in header:
                header['User-Agent'] = version_header.strip()
            else:
                header['User-Agent'] += version_header

        return header


class EdgeRc(ConfigParser):
    def __init__(self, filename):
        ConfigParser.__init__(self,
                              {'client_token': '',
                               'client_secret': '',
                               'host': '',
                               'access_token': '',
                               'max_body': '131072',
                               'headers_to_sign': 'None'})
        logger.debug("loading edgerc from %s", filename)

        self.read(expanduser(filename))

        logger.debug("successfully loaded edgerc")

    def optionxform(self, optionstr):
        """support both max_body and max-body style keys"""
        return optionstr.replace('-', '_')

    def getlist(self, section, option):
        """
            returns the named option as a list, splitting the original value
            by ','
        """
        value = self.get(section, option)
        if value:
            return value.split(',')
        else:
            return None


class EdgeGridAuth(httpx.Auth):
    def __init__(self, client_token, client_secret, access_token, headers_to_sign=(), max_body=131072):
        self.ah = EdgeGridAuthHeaders(
            client_token,
            client_secret,
            access_token,
            headers_to_sign,
            max_body
        )

    def __call__(self, r):
        timestamp = eg_timestamp()
        nonce = new_nonce()

        auth_header = self.ah.make_auth_header(
            r.url,
            r.headers,
            r.method,
            r.body,
            timestamp,
            nonce
        )
        r.register_hook('response', self.handle_redirect)
        r.headers['Authorization'] = auth_header
        logger.debug("Setting Authorization header:", auth_header)
        return r

    def sign_request(self, url, headers, method, body, timestamp, auth_header):
        return base64_hmac_sha256(
            self.make_data_to_sign(url, headers, auth_header, method, body),
            self.make_signing_key(timestamp)
        )

    def auth_flow(self, request: httpx.Request):
        logger.debug(f"Signing request: {request.method} {request.url}\n")
        logger.debug(f"Request headers before signing: {request.headers}\n")
        # Create the Authorization header
        try:
            request.headers['Authorization'] = self.ah.make_auth_header(
                request.url,
                request.headers,
                request.method,
                request.content.decode() if request.content else '',
                eg_timestamp(),
                new_nonce()
            )
        except Exception as e:
            print("Error generating auth header:", e)
            raise

        # Yield the modified request
        yield request

    @staticmethod
    def from_edgerc(rcinput, section='default'):
        """
        Returns an EdgeGridAuth object from the configuration from the given section
        of the given edgerc file.

        :param rcinput: EdgeRc instance or path to the edgerc file
        :param section: the section to use (this is the [bracketed] part of the edgerc,
            default is 'default')

        """

        if isinstance(rcinput, EdgeRc):
            rc = rcinput
        else:
            rc = EdgeRc(rcinput)

        return EdgeGridAuth(
            client_token=rc.get(section, 'client_token'),
            client_secret=rc.get(section, 'client_secret'),
            access_token=rc.get(section, 'access_token'),
            headers_to_sign=rc.getlist(section, 'headers_to_sign'),
            max_body=rc.getint(section, 'max_body')
        )
