from typing import Any
from unittest.mock import MagicMock

import pytest

from app.models.amnezia import AmneziaProperties
from app.models.subscription import SubscriptionInboundData, TCPTransportConfig, TLSConfig
from app.subscription import amnezia
from app.subscription.wireguard import WireGuardConfiguration

SETTINGS = {"private_key": "client_priv_key", "peer_ips": ["10.0.0.2/32"]}


def _exp(*packets: str) -> dict[str, Any]:
    return {"type": "noise", "settings": {"noise": [{"type": "exp", "packet": packet} for packet in packets]}}


def _finalmask(*layers: dict[str, Any]) -> dict[str, Any]:
    return {"udp": list(layers)}


def _inbound(
    finalmask: dict[str, Any] | None, amnezia_props: AmneziaProperties | None = None
) -> SubscriptionInboundData:
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
        finalmask=finalmask,
        wireguard_amnezia=amnezia_props,
    )


@pytest.fixture
def logger_mock(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    mock = MagicMock()
    monkeypatch.setattr(amnezia, "logger", mock)
    return mock


def test_exp_noise_packets_map_to_i_slots_in_order(logger_mock: MagicMock):
    finalmask = _finalmask(_exp("<b 0x01><r 8>", "<t><rd 4>"))
    assert amnezia.resolve_amnezia_settings(None, finalmask) == {"i1": "<b 0x01><r 8>", "i2": "<t><rd 4>"}
    logger_mock.warning.assert_not_called()


def test_mixed_layers_keep_only_exp_noise(logger_mock: MagicMock):
    finalmask = {
        "tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}],
        "udp": [
            {"type": "header-custom", "settings": {}},
            {
                "type": "noise",
                "settings": {"noise": [{"type": "str", "packet": "abc"}, {"type": "exp", "packet": "<r 4>"}]},
            },
        ],
    }
    assert amnezia.resolve_amnezia_settings(None, finalmask) == {"i1": "<r 4>"}
    assert logger_mock.warning.call_count == 3


def test_unsupported_xray_token_drops_only_that_packet(logger_mock: MagicMock):
    finalmask = _finalmask(_exp("<b 0x01><c 4>", "<r 4>"))
    assert amnezia.resolve_amnezia_settings(None, finalmask) == {"i1": "<r 4>"}
    assert logger_mock.warning.call_count == 1


def test_non_tag_text_packet_is_dropped(logger_mock: MagicMock):
    finalmask = _finalmask(_exp("plain text", "<n 4>", "<t>"))
    assert amnezia.resolve_amnezia_settings(None, finalmask) == {"i1": "<t>"}
    assert logger_mock.warning.call_count == 2


def test_odd_hex_packet_is_dropped_with_warning(logger_mock: MagicMock):
    finalmask = _finalmask(_exp("<b 0x123><r 4>", "<b 0xab><r 4>"))
    assert amnezia.resolve_amnezia_settings(None, finalmask) == {"i1": "<b 0xab><r 4>"}
    assert logger_mock.warning.call_count == 1


def test_more_than_five_packets_are_truncated(logger_mock: MagicMock):
    finalmask = _finalmask(_exp(*(f"<r {size}>" for size in range(1, 7))))
    settings = amnezia.resolve_amnezia_settings(None, finalmask)
    assert settings == {"i1": "<r 1>", "i2": "<r 2>", "i3": "<r 3>", "i4": "<r 4>", "i5": "<r 5>"}
    assert logger_mock.warning.call_count == 1


def test_host_packets_take_priority_and_finalmask_fills_free_slots(logger_mock: MagicMock):
    host = AmneziaProperties(jc=2, i1="<t>")
    finalmask = _finalmask(_exp("<r 4>", "<r 5>"))
    assert amnezia.resolve_amnezia_settings(host, finalmask) == {"jc": 2, "i1": "<t>", "i2": "<r 4>", "i3": "<r 5>"}


def test_host_values_without_finalmask(logger_mock: MagicMock):
    assert amnezia.resolve_amnezia_settings(AmneziaProperties(jc=4), None) == {"jc": 4}


def test_conf_and_link_include_finalmask_packets(logger_mock: MagicMock):
    inbound = _inbound(_finalmask(_exp("<b 0xc0de><r 8>")))
    generator = WireGuardConfiguration()
    generator.add(remark="test_profile", address="198.51.100.1", inbound=inbound, settings=SETTINGS)
    interface = generator.configs[0][1].split("[Peer]")[0]
    assert "I1 = <b 0xc0de><r 8>" in interface

    components = WireGuardConfiguration()._build_wireguard_components("test_profile", "198.51.100.1", inbound, SETTINGS)
    assert components is not None
    assert components["payload"]["i1"] == "<b 0xc0de><r 8>"
