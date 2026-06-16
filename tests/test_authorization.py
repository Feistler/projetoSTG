"""Gate de autorizacao (escopo)."""

import ipaddress

from stg.core.authorization import Authorization
from stg.core.models import Target


def _authz() -> Authorization:
    return Authorization(
        networks=[ipaddress.ip_network("192.168.56.0/24")],
        domains=["exemplo.local"],
    )


def test_ip_in_scope():
    assert _authz().is_authorized(Target.parse("192.168.56.10")) is True


def test_ip_out_of_scope():
    assert _authz().is_authorized(Target.parse("8.8.8.8")) is False


def test_subdomain_in_scope():
    assert _authz().is_authorized(Target.parse("app.exemplo.local")) is True


def test_apex_domain_in_scope():
    assert _authz().is_authorized(Target.parse("exemplo.local")) is True


def test_other_domain_out_of_scope():
    assert _authz().is_authorized(Target.parse("evil.com")) is False


def test_local_file_allowed_by_default():
    assert _authz().is_authorized(Target.parse("hashes.txt")) is True


def test_empty_scope_blocks_network():
    empty = Authorization(networks=[], domains=[])
    assert empty.configured is False
    assert empty.is_authorized(Target.parse("192.168.56.10")) is False
