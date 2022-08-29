"""
Test websupport client
"""
import datetime
from typing import Literal
from unittest.mock import patch

import pytest
import requests_mock

from certbot_dns_websupport._internal.dns_websupport import _WebsupportClient


@pytest.fixture
def client() -> _WebsupportClient:
    return _WebsupportClient("my_identifier", "my_secret")


@pytest.fixture
def mock_datetime():
    mocked_now = datetime.datetime.fromisoformat("2022-08-28T12:19:47.987735+00:00")
    with patch(
        "certbot_dns_websupport._internal.dns_websupport.datetime.datetime",
    ) as datetime_mock:
        datetime_mock.now.return_value = mocked_now
        yield datetime_mock


@pytest.mark.parametrize(
    ["path", "method", "authorization"],
    [
        (
            "",
            "GET",
            "Basic bXlfaWRlbnRpZmllcjpmOTY5Nzk0YzA4NmVlZTgzZDk1ZWMxMDc3Y2ZkYzMwODYwMDJiNGIw",
        ),
        (
            "",
            "POST",
            "Basic bXlfaWRlbnRpZmllcjoxNTNmZDM3NTlkNmUxMThjMTk5OTQ5ZGJmZDZmNzNmZWI4YjNhYWI3",
        ),
        (
            "",
            "DELETE",
            "Basic bXlfaWRlbnRpZmllcjo4YzNmMzkyYWRhMjk3ZGZlMzk1NzBlOTNmMDBjZDVjMjc1NmFlMDkz",
        ),
        (
            "/v1/user/self",
            "GET",
            "Basic bXlfaWRlbnRpZmllcjo3YzZlMGQ5MGI4NjI2ZGYyYWM5MzgzNTRjYmJkOGU1Y2E3NjNjZmQw",
        ),
    ],
)
@pytest.mark.usefixtures("mock_datetime")
def test_request_auth(
    client: _WebsupportClient,
    path: str,
    method: Literal["GET", "POST", "PUT", "DELETE"],
    authorization: str,
):
    data = {"status": "success"}
    with requests_mock.Mocker() as mocker:
        mocker.register_uri(
            method,
            f"https://rest.websupport.sk{path or '/'}",
            request_headers={
                "User-Agent": "python-requests/2.28.1",
                "Accept-Encoding": "gzip, deflate",
                "Accept": "application/json",
                "Connection": "keep-alive",
                "Content-Type": "application/json",
                "Date": "2022-08-28T12:19:47.987735+00:00",
                "Authorization": authorization,
            },
            json=data,
        )
        assert client._api_request(method, path) == data

    assert mocker.called


@pytest.mark.parametrize(["zone"], [("test.com",), ("sub.test.com",)])
def test_add_txt_record(client: _WebsupportClient, zone):
    with requests_mock.Mocker() as mocker:
        mocker.register_uri(
            "GET",
            "https://rest.websupport.sk/v1/user/self/zone",
            json={
                "items": [
                    {"id": 1, "name": "other.com"},
                    {"id": 2, "name": "test.com"},
                    {"id": 3, "name": "sub.test.com"},
                ],
                "pager": {"page": 1, "pagesize": None, "items": 3},
            },
        )
        mocker.register_uri(
            "POST",
            f"https://rest.websupport.sk/v1/user/self/zone/{zone}/record",
            json={"status": "success"},
        )
        client.add_txt_record(zone, f"_acme-challenge.{zone}", "challenge", 600)
    assert mocker.call_count == 2
    assert mocker.request_history[1].method == "POST"
    assert mocker.request_history[1].json() == {
        "type": "TXT",
        "name": "_acme-challenge",
        "content": "challenge",
        "ttl": 600,
    }


@pytest.mark.parametrize(["zone"], [("test.com",), ("sub.test.com",)])
@pytest.mark.parametrize(["record_missing"], [(True,), (False,)])
def test_del_txt_record(client: _WebsupportClient, zone: str, record_missing: bool):
    existing_records = {
        "items": [
            {
                "id": 1,
                "type": "A",
                "name": "@",
                "content": "37.9.169.99",
                "ttl": 600,
                "prio": None,
                "weight": None,
                "port": None,
            },
            {
                "id": 2,
                "type": "NS",
                "name": "@",
                "content": "ns1.websupport.sk",
                "ttl": 600,
                "prio": None,
                "weight": None,
                "port": None,
            },
        ],
        "pager": {"page": 1, "pagesize": None, "items": 2},
    }
    if not record_missing:
        existing_records["items"].append(
            {
                "id": 25,
                "type": "TXT",
                "name": "_acme-challenge",
                "content": "challenge",
                "ttl": 600,
                "prio": None,
                "weight": None,
                "port": None,
            },
        )

    with requests_mock.Mocker() as mocker:
        mocker.register_uri(
            "GET",
            "https://rest.websupport.sk/v1/user/self/zone",
            json={
                "items": [
                    {"id": 1, "name": "other.com"},
                    {"id": 2, "name": "test.com"},
                    {"id": 3, "name": "sub.test.com"},
                ],
                "pager": {"page": 1, "pagesize": None, "items": 3},
            },
        )
        mocker.register_uri(
            "GET",
            f"https://rest.websupport.sk/v1/user/self/zone/{zone}/record",
            json=existing_records,
        )
        mocker.register_uri(
            "DELETE",
            f"https://rest.websupport.sk/v1/user/self/zone/{zone}/record/25",
            json={"status": "success"},
        )
        client.del_txt_record(zone, f"_acme-challenge.{zone}", "challenge")
    if record_missing:
        assert mocker.call_count == 2
    else:
        assert mocker.call_count == 3
        assert mocker.request_history[2].method == "DELETE"
