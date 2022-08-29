"""DNS Authenticator for Websupport."""
import datetime
import hashlib
import hmac
import logging
from typing import Any, Callable, Literal, Optional

import requests
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

API_DOCS_URL = "https://rest.websupport.sk/docs/index"
API_URL = "https://rest.websupport.sk"


class Authenticator(dns_common.DNSAuthenticator):
    """
    DNS Authenticator for Websupport

    This Authenticator uses the Websupport API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Websupport for DNS)."
    ttl = 120

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self.client: Optional[_WebsupportClient] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None], default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Websupport credentials INI file.")

    def more_info(self) -> str:
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the Websupport API."

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        identifier = credentials.conf("identifier")
        secret_key = credentials.conf("secret_key")
        if not identifier or not secret_key:
            raise errors.PluginError(
                f"{credentials.confobj.filename}: Both dns_websupport_identifier and "
                f"dns_websupport_secret_key are required. (see {API_DOCS_URL})"
            )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "Websupport credentials INI file",
            None,
            self._validate_credentials,
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_websupport_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_websupport_client().del_txt_record(domain, validation_name, validation)

    def _get_websupport_client(self) -> "_WebsupportClient":
        if not self.credentials:
            raise errors.Error("Plugin has not been prepared.")
        if not self.client:
            self.client = _WebsupportClient(self.credentials.conf("identifier"), self.credentials.conf("secret_key"))
        return self.client


class _WebsupportClient:
    """
    Encapsulates all communication with the Websupport API.
    """

    def __init__(self, identifier: str, secret_key: str) -> None:
        self.identifier = identifier
        self.secret_key = secret_key
        self.zone: Optional[str] = None

    def _api_request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        canonicalRequest = f"{method} {path} {int(now.timestamp())}"
        signature = hmac.new(
            bytes(self.secret_key, "UTF-8"),
            bytes(canonicalRequest, "UTF-8"),
            hashlib.sha1,
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Date": now.isoformat(),
        }
        logger.debug(
            "Running API call: method %s, path %s, json_body %s, params %s",
            method,
            path,
            json_body,
            params,
        )
        request = requests.request(
            method,
            f"{API_URL}/{path.lstrip('/')}",
            params=params,
            json=json_body,
            headers=headers,
            auth=(self.identifier, signature),
        )
        try:
            request.raise_for_status()
        except requests.HTTPError as e:
            logger.debug(
                "API call failed: status code %d, text %s",
                request.status_code,
                request.text,
            )
            raise errors.PluginError(f"Error communicating with the Websupport API: {e}")
        data = request.json()
        logger.debug("API call result: %s", data)
        return data

    def _find_zone(self, domain: str) -> str:
        """
        Find the most specific available zone for domain (or subdomain).
        """
        # Certbot accept only punycode format of domain but API return utf-8 format.
        domain = domain.encode().decode("idna")
        if not self.zone:
            path = "/v1/user/self/zone"
            method = "GET"
            zone_list_data = self._api_request(method, path)
            if not zone_list_data:
                raise errors.PluginError("No zones available for Websupport account")
            zone_list = [zone["name"] for zone in zone_list_data["items"] if zone["name"]]
            zone_list.sort(key=lambda item: len(item), reverse=True)
            for zone in zone_list:
                if domain.endswith(zone):
                    self.zone = zone
                    break
            else:
                raise errors.PluginError(f"Zone not found for domain {domain}, available zones: {', '.join(zone_list)}")

        return self.zone

    def add_txt_record(self, domain: str, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Websupport zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Websupport API
        """
        zone = self._find_zone(domain)
        path = f"/v1/user/self/zone/{zone}/record"
        method = "POST"
        json_body = {
            "type": "TXT",
            "name": record_name.removesuffix(f".{zone}"),
            "content": record_content,
            "ttl": record_ttl,
        }
        self._api_request(method, path, json_body)

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Missing record is considered as correct state.

        :param str domain: The domain to use to look up the Websupport zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Websupport API
        """
        zone = self._find_zone(domain)
        path = f"/v1/user/self/zone/{zone}/record"
        method = "GET"
        response = self._api_request(method, path)
        if not response:
            return
        record_name = record_name.removesuffix(f".{zone}")
        for record in response["items"]:
            if record["type"] == "TXT" and record["name"] == record_name and record["content"] == record_content:
                break
        else:
            # record not found
            return

        self._api_request("DELETE", f"{path}/{record['id']}")
