"""Pure unit tests for WireGuard-in-Xray feature.

These tests do NOT use the FastAPI TestClient or any DB — they only exercise
the pure logic in XRayConfig and helper utilities.
"""
from __future__ import annotations

import copy
import io
import json
import zipfile

import pytest

from app.core.xray import XRayConfig
from app.models.subscription import SubscriptionInboundData, TLSConfig, TCPTransportConfig
from app.subscription.wireguard import WireGuardConfiguration
from app.utils.crypto import generate_wireguard_keypair, get_wireguard_public_key


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_wg_config(
    *,
    tag: str = "wg-in",
    port: int = 51820,
    secret_key: str | None = None,
    sniffing: dict | None = None,
    extra_inbounds: list | None = None,
) -> dict:
    """Build a minimal Xray config dict that contains one WireGuard inbound."""
    priv, _ = generate_wireguard_keypair()
    inbound: dict = {
        "tag": tag,
        "protocol": "wireguard",
        "listen": "0.0.0.0",
        "port": port,
        "settings": {
            "secretKey": secret_key or priv,
            "peers": [],
            "kernelMode": False,
        },
    }
    if sniffing is not None:
        inbound["sniffing"] = sniffing

    inbounds = [inbound] + (extra_inbounds or [])
    return {
        "log": {"loglevel": "info"},
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "DIRECT"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {"rules": []},
    }


def _vless_inbound(tag: str = "vless-tcp", port: int = 1234) -> dict:
    return {
        "tag": tag,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "streamSettings": {"network": "tcp", "tcpSettings": {}, "security": "none"},
    }


# ---------------------------------------------------------------------------
# _read_inbound / _read_wireguard_inbound
# ---------------------------------------------------------------------------


class TestXRayParseWireGuardInbound:
    def test_wg_inbound_appears_in_inbounds_by_tag(self):
        priv, pub = generate_wireguard_keypair()
        cfg = _make_wg_config(tag="wg-in", port=51820, secret_key=priv)
        parsed = XRayConfig(cfg)

        assert "wg-in" in parsed.inbounds_by_tag

    def test_wg_inbound_metadata_protocol(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        meta = XRayConfig(cfg).inbounds_by_tag["wg-in"]

        assert meta["protocol"] == "wireguard"

    def test_wg_inbound_metadata_network_and_tls(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        meta = XRayConfig(cfg).inbounds_by_tag["wg-in"]

        assert meta["network"] == "udp"
        assert meta["tls"] == "none"

    def test_wg_inbound_listen_port(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(port=12345, secret_key=priv)
        meta = XRayConfig(cfg).inbounds_by_tag["wg-in"]

        assert meta["listen_port"] == 12345

    def test_wg_inbound_public_key_derived(self):
        priv, expected_pub = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        meta = XRayConfig(cfg).inbounds_by_tag["wg-in"]

        assert meta["public_key"] == expected_pub

    def test_wg_inbound_public_key_empty_on_bad_secret(self):
        cfg = _make_wg_config()
        # Corrupt the secretKey to invalid base64
        cfg["inbounds"][0]["settings"]["secretKey"] = "not-a-valid-key!!!"
        parsed = XRayConfig(cfg)

        # Should not crash; public_key stays empty
        assert parsed.inbounds_by_tag["wg-in"]["public_key"] == ""

    def test_wg_inbound_no_pre_shared_key(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        meta = XRayConfig(cfg).inbounds_by_tag["wg-in"]

        assert meta["pre_shared_key"] is None

    def test_wg_inbound_address_is_empty(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        meta = XRayConfig(cfg).inbounds_by_tag["wg-in"]

        assert meta["address"] == []

    def test_wg_inbound_present_in_inbounds_list(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)

        assert "wg-in" in parsed.inbounds

    def test_wg_and_vless_both_parsed(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv, extra_inbounds=[_vless_inbound("vless-1")])
        parsed = XRayConfig(cfg)

        assert "wg-in" in parsed.inbounds_by_tag
        assert "vless-1" in parsed.inbounds_by_tag

    def test_excluded_wg_tag_not_in_inbounds_by_tag(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg, exclude_inbound_tags={"wg-in"})

        assert "wg-in" not in parsed.inbounds_by_tag

    def test_excluded_wg_tag_but_vless_still_parsed(self):
        cfg = _make_wg_config(extra_inbounds=[_vless_inbound("v")])
        parsed = XRayConfig(cfg, exclude_inbound_tags={"wg-in"})

        assert "wg-in" not in parsed.inbounds_by_tag
        assert "v" in parsed.inbounds_by_tag

    def test_wg_inbound_missing_tag_raises_validation_error(self):
        cfg = _make_wg_config()
        cfg["inbounds"][0].pop("tag")
        # _validate() rejects any inbound without a tag before _read_inbound is called
        with pytest.raises(ValueError, match="unique tag"):
            XRayConfig(cfg)

    def test_wg_inbound_missing_tag_skipped_with_skip_validation(self):
        cfg = _make_wg_config()
        cfg["inbounds"][0].pop("tag")
        # With skip_validation=True the tagless inbound is silently ignored by _read_wireguard_inbound
        parsed = XRayConfig(cfg, skip_validation=True)
        wg_tags = [k for k, v in parsed.inbounds_by_tag.items() if v["protocol"] == "wireguard"]
        assert len(wg_tags) == 0

    def test_multiple_wg_inbounds(self):
        priv1, _ = generate_wireguard_keypair()
        priv2, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(tag="wg1", port=51820, secret_key=priv1)
        cfg["inbounds"].append({
            "tag": "wg2",
            "protocol": "wireguard",
            "listen": "0.0.0.0",
            "port": 51821,
            "settings": {"secretKey": priv2, "peers": []},
        })
        parsed = XRayConfig(cfg)

        assert "wg1" in parsed.inbounds_by_tag
        assert "wg2" in parsed.inbounds_by_tag
        assert parsed.inbounds_by_tag["wg1"]["listen_port"] == 51820
        assert parsed.inbounds_by_tag["wg2"]["listen_port"] == 51821


# ---------------------------------------------------------------------------
# with_wg_peers
# ---------------------------------------------------------------------------


class TestWithWgPeers:
    def test_peers_injected_into_matching_inbound(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        parsed = XRayConfig(cfg)

        peer_pub, _ = generate_wireguard_keypair()
        peer_map = {"wg-in": [{"publicKey": peer_pub, "allowedIPs": ["10.0.0.2/32"]}]}

        enriched = parsed.with_wg_peers(peer_map)
        wg = next(ib for ib in enriched["inbounds"] if ib["tag"] == "wg-in")
        assert wg["settings"]["peers"] == peer_map["wg-in"]

    def test_original_config_not_mutated(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        original_peers_snapshot = copy.deepcopy(
            next(ib for ib in parsed["inbounds"] if ib["tag"] == "wg-in")["settings"]["peers"]
        )
        peer_pub, _ = generate_wireguard_keypair()
        parsed.with_wg_peers({"wg-in": [{"publicKey": peer_pub, "allowedIPs": ["10.0.0.5/32"]}]})

        current_peers = next(ib for ib in parsed["inbounds"] if ib["tag"] == "wg-in")["settings"]["peers"]
        assert current_peers == original_peers_snapshot

    def test_nonexistent_tag_does_not_raise(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        enriched = parsed.with_wg_peers({"no-such-tag": [{"publicKey": "x", "allowedIPs": []}]})
        wg = next(ib for ib in enriched["inbounds"] if ib["tag"] == "wg-in")
        assert wg["settings"]["peers"] == []

    def test_empty_peer_map_leaves_peers_unchanged(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        # Pre-populate some peers in the config itself
        peer_pub, _ = generate_wireguard_keypair()
        cfg["inbounds"][0]["settings"]["peers"] = [{"publicKey": peer_pub, "allowedIPs": ["10.0.0.2/32"]}]
        parsed = XRayConfig(cfg)

        enriched = parsed.with_wg_peers({})
        wg = next(ib for ib in enriched["inbounds"] if ib["tag"] == "wg-in")
        # No tag matched → peers unchanged
        assert len(wg["settings"]["peers"]) == 1

    def test_returns_dict(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        result = parsed.with_wg_peers({})
        assert isinstance(result, dict)

    def test_multiple_peers_injected(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        peers = [
            {"publicKey": generate_wireguard_keypair()[0], "allowedIPs": [f"10.0.0.{i}/32"]}
            for i in range(2, 52)
        ]
        enriched = parsed.with_wg_peers({"wg-in": peers})
        wg = next(ib for ib in enriched["inbounds"] if ib["tag"] == "wg-in")
        assert len(wg["settings"]["peers"]) == 50

    def test_vless_inbound_not_touched(self):
        cfg = _make_wg_config(extra_inbounds=[_vless_inbound("vless-1")])
        parsed = XRayConfig(cfg)
        peer_pub, _ = generate_wireguard_keypair()
        enriched = parsed.with_wg_peers({"wg-in": [{"publicKey": peer_pub, "allowedIPs": ["10.0.0.2/32"]}]})

        vless = next(ib for ib in enriched["inbounds"] if ib["tag"] == "vless-1")
        assert "peers" not in vless.get("settings", {})

    def test_multiple_wg_inbounds_independent_peers(self):
        priv1, _ = generate_wireguard_keypair()
        priv2, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(tag="wg1", secret_key=priv1)
        cfg["inbounds"].append({
            "tag": "wg2",
            "protocol": "wireguard",
            "listen": "0.0.0.0",
            "port": 51821,
            "settings": {"secretKey": priv2, "peers": []},
        })
        parsed = XRayConfig(cfg)
        pub1, _ = generate_wireguard_keypair()
        pub2, _ = generate_wireguard_keypair()
        enriched = parsed.with_wg_peers({
            "wg1": [{"publicKey": pub1, "allowedIPs": ["10.0.1.2/32"]}],
            "wg2": [{"publicKey": pub2, "allowedIPs": ["10.0.2.2/32"]}],
        })

        wg1 = next(ib for ib in enriched["inbounds"] if ib["tag"] == "wg1")
        wg2 = next(ib for ib in enriched["inbounds"] if ib["tag"] == "wg2")
        assert wg1["settings"]["peers"][0]["publicKey"] == pub1
        assert wg2["settings"]["peers"][0]["publicKey"] == pub2


# ---------------------------------------------------------------------------
# with_wg_sniffing
# ---------------------------------------------------------------------------


class TestWithWgSniffing:
    def test_sniffing_added_to_wg_inbound(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        result = parsed.with_wg_sniffing()

        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")
        assert wg["sniffing"]["enabled"] is True

    def test_sniffing_destoverride_contains_tls(self):
        cfg = _make_wg_config()
        result = XRayConfig(cfg).with_wg_sniffing()
        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")
        assert "tls" in wg["sniffing"]["destOverride"]

    def test_sniffing_route_only_is_true(self):
        cfg = _make_wg_config()
        result = XRayConfig(cfg).with_wg_sniffing()
        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")
        assert wg["sniffing"].get("routeOnly") is True

    def test_existing_sniffing_not_overwritten(self):
        existing = {"enabled": False, "destOverride": ["http"]}
        cfg = _make_wg_config(sniffing=existing)
        result = XRayConfig(cfg).with_wg_sniffing()
        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")

        # Must remain exactly as defined — not overwritten
        assert wg["sniffing"]["enabled"] is False
        assert wg["sniffing"]["destOverride"] == ["http"]

    def test_returns_xrayconfig_instance(self):
        cfg = _make_wg_config()
        result = XRayConfig(cfg).with_wg_sniffing()
        assert isinstance(result, XRayConfig)

    def test_original_not_mutated(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        original_wg = next(ib for ib in parsed["inbounds"] if ib["tag"] == "wg-in")
        had_sniffing = "sniffing" in original_wg

        parsed.with_wg_sniffing()
        still_has = "sniffing" in next(ib for ib in parsed["inbounds"] if ib["tag"] == "wg-in")
        assert still_has == had_sniffing  # unchanged

    def test_vless_inbound_not_touched_by_sniffing(self):
        cfg = _make_wg_config(extra_inbounds=[_vless_inbound("vless-1")])
        result = XRayConfig(cfg).with_wg_sniffing()
        vless = next(ib for ib in result["inbounds"] if ib["tag"] == "vless-1")
        assert "sniffing" not in vless

    def test_sniffing_preserved_on_roundtrip_json(self):
        """with_wg_sniffing result survives JSON serialization (used in connect_node)."""
        cfg = _make_wg_config()
        result = XRayConfig(cfg).with_wg_sniffing()
        json_str = result.to_str()
        reloaded = json.loads(json_str)
        wg = next(ib for ib in reloaded["inbounds"] if ib["tag"] == "wg-in")
        assert wg["sniffing"]["enabled"] is True

    def test_inbounds_by_tag_still_has_wg(self):
        """After with_wg_sniffing the returned XRayConfig must have WG in inbounds_by_tag."""
        cfg = _make_wg_config()
        result = XRayConfig(cfg).with_wg_sniffing()
        assert "wg-in" in result.inbounds_by_tag

    def test_multiple_wg_inbounds_all_get_sniffing(self):
        priv1, _ = generate_wireguard_keypair()
        priv2, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(tag="wg1", secret_key=priv1)
        cfg["inbounds"].append({
            "tag": "wg2",
            "protocol": "wireguard",
            "listen": "0.0.0.0",
            "port": 51821,
            "settings": {"secretKey": priv2, "peers": []},
        })
        result = XRayConfig(cfg).with_wg_sniffing()
        for tag in ("wg1", "wg2"):
            wg = next(ib for ib in result["inbounds"] if ib["tag"] == tag)
            assert wg["sniffing"]["enabled"] is True


# ---------------------------------------------------------------------------
# Combined pipeline: sniffing → peers → JSON (mirrors connect_node flow)
# ---------------------------------------------------------------------------


class TestConnectNodePipeline:
    def test_full_pipeline_produces_valid_json(self):
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        parsed = XRayConfig(cfg)

        peer_pub, _ = generate_wireguard_keypair()
        peer_map = {"wg-in": [{"publicKey": peer_pub, "allowedIPs": ["10.0.0.2/32"]}]}

        enriched = parsed.with_wg_sniffing()
        config_str = json.dumps(enriched.with_wg_peers(peer_map))
        result = json.loads(config_str)

        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")
        assert wg["sniffing"]["enabled"] is True
        assert wg["settings"]["peers"][0]["publicKey"] == peer_pub
        assert wg["settings"]["secretKey"] == priv

    def test_pipeline_with_no_wg_inbounds(self):
        """Pipeline is safe when config has no WG inbounds."""
        cfg = {
            "log": {"loglevel": "info"},
            "inbounds": [_vless_inbound("vless-only")],
            "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}, {"protocol": "blackhole", "tag": "BLOCK"}],
            "routing": {"rules": []},
        }
        parsed = XRayConfig(cfg)
        enriched = parsed.with_wg_sniffing()
        config_str = json.dumps(enriched.with_wg_peers({}))
        result = json.loads(config_str)
        assert result["inbounds"][0]["tag"] == "vless-only"

    def test_pipeline_empty_peer_map_still_valid(self):
        cfg = _make_wg_config()
        parsed = XRayConfig(cfg)
        config_str = json.dumps(parsed.with_wg_sniffing().with_wg_peers({}))
        result = json.loads(config_str)
        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")
        assert wg["settings"]["peers"] == []
        assert wg["sniffing"]["enabled"] is True

    def test_1000_peers_inject_performance(self):
        """Inject 1000 peers and verify all appear in output (performance baseline)."""
        priv, _ = generate_wireguard_keypair()
        cfg = _make_wg_config(secret_key=priv)
        parsed = XRayConfig(cfg)

        peers = [
            {"publicKey": generate_wireguard_keypair()[0], "allowedIPs": [f"10.{i//256}.{i%256}.0/32"]}
            for i in range(1000)
        ]
        enriched = parsed.with_wg_sniffing()
        config_str = json.dumps(enriched.with_wg_peers({"wg-in": peers}))
        result = json.loads(config_str)
        wg = next(ib for ib in result["inbounds"] if ib["tag"] == "wg-in")
        assert len(wg["settings"]["peers"]) == 1000


# ---------------------------------------------------------------------------
# get_wireguard_inbound_tags_from_db — sync logic test via in-memory mocks
# ---------------------------------------------------------------------------


class TestGetWireguardInboundTagsLogic:
    """Test the tag extraction logic without touching a real DB.
    
    We pass mock CoreConfig-like objects directly into the function's internal logic
    (reimplementing the relevant part) to verify the scanning algorithm.
    """

    @staticmethod
    def _simulate_tags(rows: list[dict]) -> set[str]:
        """
        Mirrors the logic of get_wireguard_inbound_tags_from_db without a DB session.
        Each row dict must have {"type": CoreType value, "config": dict}.
        """
        import json as _json
        from app.db.models import CoreType

        tags: set[str] = set()
        for row in rows:
            cfg = row.get("config") or {}
            if isinstance(cfg, str):
                cfg = _json.loads(cfg)
            if not isinstance(cfg, dict):
                continue
            row_type = row.get("type")
            if row_type == CoreType.wg:
                name = cfg.get("interface_name")
                if name:
                    tags.add(str(name).strip())
            elif row_type == CoreType.xray:
                for inbound in cfg.get("inbounds", []):
                    if inbound.get("protocol") == "wireguard":
                        tag = inbound.get("tag", "").strip()
                        if tag:
                            tags.add(tag)
        return tags

    def test_type_wg_returns_interface_name(self):
        from app.db.models import CoreType
        rows = [{"type": CoreType.wg, "config": {"interface_name": "wg0", "listen_port": 51820, "address": []}}]
        assert self._simulate_tags(rows) == {"wg0"}

    def test_type_xray_returns_wg_inbound_tags(self):
        from app.db.models import CoreType
        priv, _ = generate_wireguard_keypair()
        rows = [{
            "type": CoreType.xray,
            "config": {
                "inbounds": [
                    {"tag": "wg-in", "protocol": "wireguard", "port": 51820,
                     "settings": {"secretKey": priv, "peers": []}},
                    {"tag": "vless-1", "protocol": "vless", "port": 443,
                     "settings": {"clients": []}},
                ],
                "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}],
            },
        }]
        assert self._simulate_tags(rows) == {"wg-in"}

    def test_mixed_cores_all_tags_collected(self):
        from app.db.models import CoreType
        priv, _ = generate_wireguard_keypair()
        rows = [
            {"type": CoreType.wg, "config": {"interface_name": "wg-legacy", "listen_port": 51820, "address": []}},
            {"type": CoreType.xray, "config": {
                "inbounds": [{"tag": "wg-xray", "protocol": "wireguard", "port": 51821,
                              "settings": {"secretKey": priv, "peers": []}}],
                "outbounds": [],
            }},
        ]
        assert self._simulate_tags(rows) == {"wg-legacy", "wg-xray"}

    def test_empty_rows(self):
        assert self._simulate_tags([]) == set()

    def test_xray_core_with_no_wg_inbounds(self):
        from app.db.models import CoreType
        rows = [{"type": CoreType.xray, "config": {
            "inbounds": [{"tag": "vless", "protocol": "vless", "port": 443}],
            "outbounds": [],
        }}]
        assert self._simulate_tags(rows) == set()

    def test_wg_inbound_without_tag_skipped(self):
        from app.db.models import CoreType
        priv, _ = generate_wireguard_keypair()
        rows = [{"type": CoreType.xray, "config": {
            "inbounds": [{"protocol": "wireguard", "port": 51820,
                          "settings": {"secretKey": priv, "peers": []}}],  # no "tag"
            "outbounds": [],
        }}]
        assert self._simulate_tags(rows) == set()

    def test_config_as_json_string(self):
        from app.db.models import CoreType
        cfg = json.dumps({"interface_name": "wg-str", "listen_port": 51820, "address": []})
        rows = [{"type": CoreType.wg, "config": cfg}]
        assert self._simulate_tags(rows) == {"wg-str"}


# ---------------------------------------------------------------------------
# get_wg_peer_map_from_db — logic test via in-memory simulation
# ---------------------------------------------------------------------------


class TestGetWgPeerMapLogic:
    """Verify the peer-map assembly logic without a real DB."""

    @staticmethod
    def _build_peer_map(
        users: list[dict],
        inbound_tags: set[str],
    ) -> dict[str, list[dict]]:
        """
        Mirrors the core of get_wg_peer_map_from_db without SQL.
        Each user dict: {"proxy_settings": {...}, "user_inbound_tags": [...]}.
        """
        peer_map: dict[str, list[dict]] = {t: [] for t in inbound_tags}
        for user in users:
            user_tags = set(user.get("user_inbound_tags") or []) & inbound_tags
            if not user_tags:
                continue
            wg = (user.get("proxy_settings") or {}).get("wireguard", {})
            public_key = wg.get("public_key")
            peer_ips = wg.get("peer_ips") or []
            if not public_key or not peer_ips:
                continue
            for tag in user_tags:
                peer_map[tag].append({"publicKey": public_key, "allowedIPs": list(peer_ips)})
        return peer_map

    def _user(self, pub: str, peer_ips: list[str], tags: list[str]) -> dict:
        return {
            "proxy_settings": {"wireguard": {"public_key": pub, "peer_ips": peer_ips}},
            "user_inbound_tags": tags,
        }

    def test_single_user_single_inbound(self):
        pub, _ = generate_wireguard_keypair()
        users = [self._user(pub, ["10.0.0.2/32"], ["wg-in"])]
        result = self._build_peer_map(users, {"wg-in"})
        assert len(result["wg-in"]) == 1
        assert result["wg-in"][0]["publicKey"] == pub
        assert result["wg-in"][0]["allowedIPs"] == ["10.0.0.2/32"]

    def test_user_with_no_wg_keys_excluded(self):
        users = [{"proxy_settings": {"wireguard": {}}, "user_inbound_tags": ["wg-in"]}]
        result = self._build_peer_map(users, {"wg-in"})
        assert result["wg-in"] == []

    def test_user_with_no_peer_ips_excluded(self):
        pub, _ = generate_wireguard_keypair()
        users = [{"proxy_settings": {"wireguard": {"public_key": pub, "peer_ips": []}},
                  "user_inbound_tags": ["wg-in"]}]
        result = self._build_peer_map(users, {"wg-in"})
        assert result["wg-in"] == []

    def test_user_in_wrong_inbound_excluded(self):
        pub, _ = generate_wireguard_keypair()
        users = [self._user(pub, ["10.0.0.2/32"], ["different-wg"])]
        result = self._build_peer_map(users, {"wg-in"})
        assert result["wg-in"] == []

    def test_multiple_users_multiple_peers(self):
        pubs = [generate_wireguard_keypair()[0] for _ in range(5)]
        users = [self._user(p, [f"10.0.0.{i+2}/32"], ["wg-in"]) for i, p in enumerate(pubs)]
        result = self._build_peer_map(users, {"wg-in"})
        assert len(result["wg-in"]) == 5
        result_keys = {e["publicKey"] for e in result["wg-in"]}
        assert result_keys == set(pubs)

    def test_user_spans_multiple_wg_inbounds(self):
        pub, _ = generate_wireguard_keypair()
        users = [self._user(pub, ["10.0.0.2/32"], ["wg1", "wg2"])]
        result = self._build_peer_map(users, {"wg1", "wg2"})
        assert len(result["wg1"]) == 1
        assert len(result["wg2"]) == 1

    def test_empty_inbound_tags_returns_empty(self):
        pub, _ = generate_wireguard_keypair()
        users = [self._user(pub, ["10.0.0.2/32"], ["wg-in"])]
        result = self._build_peer_map(users, set())
        assert result == {}

    def test_1000_users_all_appear(self):
        users = [
            self._user(generate_wireguard_keypair()[0], [f"10.{i//256}.{i%256}.0/32"], ["wg-in"])
            for i in range(1000)
        ]
        result = self._build_peer_map(users, {"wg-in"})
        assert len(result["wg-in"]) == 1000


# ---------------------------------------------------------------------------
# Subscription .conf generation for WG-in-Xray
# ---------------------------------------------------------------------------

class TestWireGuardConfGeneration:
    """Tests that WireGuardConfiguration.add() produces correct .conf content
    for a WireGuard-as-Xray-inbound scenario."""

    def _make_inbound(
        self,
        server_public_key: str,
        port: int = 51820,
        allowed_ips: list[str] | None = None,
        dns: list[str] | None = None,
        keepalive: int | None = None,
        mtu: int | None = None,
    ) -> SubscriptionInboundData:
        return SubscriptionInboundData(
            remark="WG-Test",
            inbound_tag="wg-in",
            protocol="wireguard",
            address="1.2.3.4",
            port=port,
            network="udp",
            tls_config=TLSConfig(),
            transport_config=TCPTransportConfig(path="", host=[]),
            wireguard_public_key=server_public_key,
            wireguard_allowed_ips=allowed_ips or ["0.0.0.0/0", "::/0"],
            wireguard_dns=dns,
            wireguard_keepalive=keepalive,
            wireguard_mtu=mtu,
        )

    def _extract_conf(self, wg_conf: WireGuardConfiguration) -> str:
        zip_bytes = wg_conf.render()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert len(zf.namelist()) == 1
            return zf.read(zf.namelist()[0]).decode()

    def test_basic_conf_generated(self):
        priv, pub_server = generate_wireguard_keypair()
        _, pub_client = generate_wireguard_keypair()
        # server public key is what we use as wireguard_public_key
        inbound = self._make_inbound(server_public_key=pub_server)
        settings = {"private_key": priv, "peer_ips": ["10.0.0.2/32"]}

        wg = WireGuardConfiguration()
        wg.add(remark="WG-Test", address="1.2.3.4", inbound=inbound, settings=settings)
        conf = self._extract_conf(wg)

        assert "[Interface]" in conf
        assert "[Peer]" in conf
        assert f"PrivateKey = {priv}" in conf
        assert "Address = 10.0.0.2/32" in conf
        assert f"PublicKey = {pub_server}" in conf
        assert "Endpoint = 1.2.3.4:51820" in conf
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf

    def test_dns_included_in_conf(self):
        priv, pub_server = generate_wireguard_keypair()
        inbound = self._make_inbound(server_public_key=pub_server, dns=["1.1.1.1", "8.8.8.8"])
        settings = {"private_key": priv, "peer_ips": ["10.0.0.2/32"]}

        wg = WireGuardConfiguration()
        wg.add(remark="WG-DNS", address="1.2.3.4", inbound=inbound, settings=settings)
        conf = self._extract_conf(wg)

        assert "DNS = 1.1.1.1, 8.8.8.8" in conf

    def test_keepalive_and_mtu(self):
        priv, pub_server = generate_wireguard_keypair()
        inbound = self._make_inbound(server_public_key=pub_server, keepalive=25, mtu=1280)
        settings = {"private_key": priv, "peer_ips": ["10.0.0.2/32"]}

        wg = WireGuardConfiguration()
        wg.add(remark="WG-KA", address="1.2.3.4", inbound=inbound, settings=settings)
        conf = self._extract_conf(wg)

        assert "PersistentKeepalive = 25" in conf
        assert "MTU = 1280" in conf

    def test_missing_private_key_skipped(self):
        _, pub_server = generate_wireguard_keypair()
        inbound = self._make_inbound(server_public_key=pub_server)
        settings = {"private_key": "", "peer_ips": ["10.0.0.2/32"]}

        wg = WireGuardConfiguration()
        wg.add(remark="WG-NoKey", address="1.2.3.4", inbound=inbound, settings=settings)
        # No configs added — render returns empty zip
        zip_bytes = wg.render()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert len(zf.namelist()) == 0

    def test_xray_wg_inbound_public_key_matches_conf(self):
        """XRayConfig parses secretKey → derives public_key; .conf uses that public_key."""
        priv_server, pub_server = generate_wireguard_keypair()
        xray_cfg = _make_wg_config(secret_key=priv_server)
        cfg = XRayConfig(xray_cfg)
        inbound_meta = cfg._inbounds_by_tag["wg-in"]

        assert inbound_meta["public_key"] == pub_server

        # Simulate what hosts.py does for subscription
        priv_client, _ = generate_wireguard_keypair()
        inbound = self._make_inbound(
            server_public_key=inbound_meta["public_key"],
            port=inbound_meta["listen_port"],
        )
        settings = {"private_key": priv_client, "peer_ips": ["10.0.0.5/32"]}

        wg = WireGuardConfiguration()
        wg.add(remark="Xray-WG", address="server.example.com", inbound=inbound, settings=settings)
        conf = self._extract_conf(wg)

        assert f"PublicKey = {pub_server}" in conf
        assert f"PrivateKey = {priv_client}" in conf
        assert "Endpoint = server.example.com:51820" in conf
