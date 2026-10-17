import base64

import pytest
from pydantic import ValidationError

from app.models.amnezia import AmneziaProperties
from app.models.subscription import SubscriptionInboundData, TCPTransportConfig, TLSConfig
from app.subscription.singbox import SingBoxConfiguration
from app.subscription.wireguard import WireGuardConfiguration

VALID_KEY = base64.b64encode(b"k" * 32).decode()
VALID_PACKET = "<b 0x474554><r 16>"


def _inbound(amnezia: AmneziaProperties | None) -> SubscriptionInboundData:
    return SubscriptionInboundData(
        remark="test_profile",
        inbound_tag="wg_inbound",
        tls_config=TLSConfig(),
        transport_config=TCPTransportConfig(),
        priority=1,
        protocol="wireguard",
        network="udp",
        port=51820,
        wireguard_public_key="server_pub_key",
        wireguard_allowed_ips=["0.0.0.0/0"],
        wireguard_amnezia=amnezia,
    )


SETTINGS = {"private_key": "client_priv_key", "peer_ips": ["10.0.0.2/32"]}


def test_valid_values_are_accepted_and_normalized():
    props = AmneziaProperties(
        jc=4,
        jmin=40,
        jmax=70,
        s1=12,
        s2=12,
        s3=12,
        s4=12,
        h1="1",
        h2=" 10 - 20 ",
        h3="2147483647",
        h4="3-9",
        i1=VALID_PACKET,
        i2="<rd 8><rc 4><t>",
        header_protection_key=VALID_KEY,
        content_padding_addition="0-16",
        rekey_after_time="(off)",
        rekey_timeout=5,
        reject_after_time="100-200",
        keepalive_timeout="10",
        max_handshake_attempts=18,
        random_trailers="On",
        disable_cookies="off",
    )
    dumped = props.model_dump(exclude_none=True)
    assert dumped["h2"] == "10-20"
    assert dumped["h3"] == "2147483647"
    assert dumped["rekey_after_time"] == "(off)"
    assert dumped["keepalive_timeout"] == 10
    assert dumped["reject_after_time"] == "100-200"
    assert dumped["random_trailers"] == "on"
    assert dumped["disable_cookies"] == "off"


def test_blank_values_are_omitted():
    props = AmneziaProperties(jc="", i1=" ", header_protection_key="", rekey_after_time="", random_trailers="")
    assert props.model_dump(exclude_none=True) == {}


@pytest.mark.parametrize(
    "fields",
    [
        {"jmin": 80, "jmax": 40},
        {"jc": -1},
        {"jc": 65536},
        {"jc": True},
        {"s1": 70000},
        {"h1": "9-3"},
        {"h1": "4294967296"},
        {"h1": "a-b"},
        {"i1": "plain text"},
        {"i1": "<b 0x123><r 4>"},
        {"i1": "<c 4>"},
        {"i1": "<n 4>"},
        {"i1": "<r>"},
        {"i1": "<t 1>"},
        {"i1": "<b 0x41>text"},
        {"i1": "<b 0x41"},
        {"header_protection_key": "my_hp_key", "s1": 12, "s2": 12, "s3": 12, "s4": 12},
        {"header_protection_key": base64.b64encode(b"a" * 16).decode(), "s1": 12, "s2": 12, "s3": 12, "s4": 12},
        {"header_protection_key": VALID_KEY, "s1": 11, "s2": 12, "s3": 12, "s4": 12},
        {"header_protection_key": VALID_KEY, "s1": 12, "s2": 12, "s3": 12},
        {"rekey_after_time": "180-120"},
        {"rekey_after_time": "70000"},
        {"rekey_after_time": "-5"},
        {"content_padding_addition": "1-2-3"},
        {"random_trailers": "yes"},
        {"disable_cookies": "1"},
    ],
)
def test_invalid_values_are_rejected(fields):
    with pytest.raises(ValidationError):
        AmneziaProperties(**fields)


@pytest.mark.parametrize("packet", ["<b 0x123><r 4>", "<b 0xabc>"])
def test_odd_hex_packet_raises_clear_error(packet):
    with pytest.raises(ValidationError, match="even length"):
        AmneziaProperties(i1=packet)


def test_raw_dict_in_subscription_is_validated():
    with pytest.raises(ValidationError):
        _inbound({"header_protection_key": "my_hp_key"})


def test_wireguard_conf_contains_amnezia_directives():
    amnezia = AmneziaProperties(
        jc=4,
        jmin=40,
        jmax=70,
        h1="1",
        i1=VALID_PACKET,
        rekey_after_time="120-180",
        random_trailers="on",
        disable_cookies="off",
    )
    generator = WireGuardConfiguration()
    generator.add(remark="test_profile", address="198.51.100.1", inbound=_inbound(amnezia), settings=SETTINGS)
    content = generator.configs[0][1]
    interface, peer = content.split("[Peer]")
    for line in (
        "Jc = 4",
        "Jmin = 40",
        "Jmax = 70",
        "H1 = 1",
        f"I1 = {VALID_PACKET}",
        "RekeyAfterTime = 120-180",
        "RandomTrailers = on",
        "DisableCookies = off",
    ):
        assert line in interface
    assert "Jc" not in peer


def test_wireguard_link_payload_contains_amnezia_fields():
    amnezia = AmneziaProperties(jc=4, i1=VALID_PACKET, disable_cookies="on")
    components = WireGuardConfiguration()._build_wireguard_components(
        "test_profile", "198.51.100.1", _inbound(amnezia), SETTINGS
    )
    assert components is not None
    assert components["payload"]["jc"] == 4
    assert components["payload"]["i1"] == VALID_PACKET
    assert components["payload"]["disable_cookies"] == "on"
    assert "jc=4" in components["uri"]
    assert "disable_cookies=on" in components["uri"]


def test_singbox_endpoint_ignores_amnezia():
    amnezia = AmneziaProperties(
        jc=4,
        header_protection_key=VALID_KEY,
        s1=12,
        s2=12,
        s3=12,
        s4=12,
        rekey_after_time="120",
        random_trailers="on",
    )
    endpoint = SingBoxConfiguration()._build_wireguard(
        remark="test_profile", address="198.51.100.1", inbound=_inbound(amnezia), settings=SETTINGS
    )
    assert endpoint["type"] == "wireguard"
    assert "jc" not in endpoint
    assert "header_protection_key" not in endpoint
    assert "random_trailers" not in endpoint
