"""
Integration tests with certbot
"""

from unittest import mock

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_websupport._internal.dns_websupport import Authenticator


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    def setUp(self):

        super().setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "dns_websupport_identifier": "my_identifier",
                "dns_websupport_secret_key": "my_secret",
            },
            path,
        )

        self.config = mock.MagicMock(
            dns_websupport_credentials=path, dns_websupport_propagation_seconds=0
        )

        self.auth = Authenticator(self.config, "dns-websupport")

        self.mock_client = mock.MagicMock()
        self.auth._get_websupport_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, _):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY, mock.ANY)
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_no_creds(self):
        dns_test_common.write({}, self.config.dns_websupport_credentials)
        self.assertRaises(errors.PluginError, self.auth.perform, [self.achall])

    def test_missing_email_or_key(self):
        dns_test_common.write(
            {"dns_websupport_identifier": "my_identifier"}, self.config.dns_websupport_credentials
        )
        self.assertRaises(errors.PluginError, self.auth.perform, [self.achall])

        dns_test_common.write(
            {"dns_websupport_secret_key": "my_secret"}, self.config.dns_websupport_credentials
        )
        self.assertRaises(errors.PluginError, self.auth.perform, [self.achall])
