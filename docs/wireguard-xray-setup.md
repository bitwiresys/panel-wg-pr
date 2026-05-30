# WireGuard-as-Xray-Inbound: Setup Guide

This guide explains how to configure **WireGuard inside Xray** (`CoreType.xray` + `protocol: wireguard`) so that WireGuard clients benefit from Xray's traffic inspection (sniffing) and SNI-based routing (e.g. Russia → DIRECT, foreign → proxy).

> **Why not the separate WireGuard backend (`CoreType.wg`)?**
> The old kernel-module WireGuard backend is a plain tunnel — it cannot inspect or route traffic by protocol/SNI. WireGuard-as-Xray-inbound passes all client traffic through Xray's routing engine, enabling per-domain or per-IP rules without requiring a second hop.

---

## Prerequisites

- PasarGuard panel installed and running
- A node reachable on a UDP port (default `51820`)
- Node running **patched** `pasarguard-node` + Xray with WireGuard **UserManager** (see repo `docs/wireguard-xray-integration.md`)

---

## Step 1 — Create an Xray Core with WireGuard Inbound

### 1.1 Open Core Config

Dashboard → **Nodes** → **Cores** → **Add Core** → select type **xray**.

### 1.2 Generate keypair + apply template

Click **"Insert WireGuard-in-Xray template"** — the editor will be pre-filled with a working Xray JSON and a generated keypair will be shown. **Copy the public key** — you'll need it later.

### 1.3 Minimal Xray JSON

If you prefer to write it manually:

```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "wg-in",
      "protocol": "wireguard",
      "listen": "0.0.0.0",
      "port": 51820,
      "settings": {
        "secretKey": "<SERVER_PRIVATE_KEY_BASE64>",
        "address": ["10.0.0.1/32"],
        "peers": [],
        "kernelMode": false,
        "mtu": 1420
      }
    }
  ],
  "outbounds": [
    { "tag": "DIRECT", "protocol": "freedom" },
    { "tag": "BLOCK",  "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["wg-in"],
        "domain": ["geosite:category-ru"],
        "outboundTag": "DIRECT"
      },
      {
        "type": "field",
        "inboundTag": ["wg-in"],
        "ip": ["geoip:ru"],
        "outboundTag": "DIRECT"
      }
    ]
  }
}
```

Key points:
- `kernelMode: false` — required, runs WireGuard in userspace (no kernel module needed)
- `peers: []` — the panel fills this automatically on every `connect_node`
- Sniffing is added automatically by the panel (`routeOnly: true`, so packets are not re-routed but the routing rules use the sniffed destination)

### 1.4 Routing rules explained

| Rule | Effect |
|------|--------|
| `geosite:category-ru` → DIRECT | Russian domains go directly through the node's network |
| `geoip:ru` → DIRECT | Russian IPs go directly |
| (implicit fallback) | Everything else uses the default outbound (add a PROXY outbound if needed) |

To add a proxy outbound (e.g. VLESS to another server):

```json
{
  "tag": "PROXY",
  "protocol": "vless",
  "settings": { ... },
  "streamSettings": { ... }
}
```

Then change the last routing rule's `outboundTag` to `"PROXY"`.

---

## Step 2 — OS-level Forwarding and NAT on the Node

WireGuard clients will send traffic through Xray, which exits via the `DIRECT` outbound (the node's own network interface). You must enable IP forwarding and NAT on the node OS.

```bash
# Enable IPv4 forwarding (persistent)
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT for WireGuard clients (replace eth0 with your outbound interface)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Make iptables rule persistent (Debian/Ubuntu)
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

To find your outbound interface: `ip route | grep default`

> **Note:** NAT is only needed if Xray forwards traffic through `DIRECT` outbound to the internet. If you use a chain proxy (VLESS/VMESS outbound), NAT on the WireGuard node may not be required.

---

## Step 3 — Create a Group

Dashboard → **Groups** → **Add Group** → select the `wg-in` inbound (it now appears with a **WireGuard** badge in the selector).

---

## Step 4 — Create a Host

Dashboard → **Hosts** → **Add Host**:

- **Inbound**: select `wg-in` (WireGuard badge will appear)
- **Address**: your node's public IP or domain
- **Port**: auto-filled from the inbound's `listen_port` (51820)
- Optionally configure **AllowedIPs**, **DNS**, **MTU**, **Keepalive** in the WireGuard overrides section

The **server public key** (derived from `secretKey`) is shown in the form — verify it matches the keypair you generated in Step 1.

---

## Step 5 — Create a User

Dashboard → **Users** → **Add User** → assign to the WireGuard group.

The panel automatically:
1. Generates a WireGuard keypair for the user
2. Allocates `peer_ips` (e.g. `10.0.0.2/32`)
3. Includes the user's public key in the peers list sent to the node

---

## Step 6 — Get the `.conf` File

User's subscription → format **WireGuard** → download `.zip` → extract `.conf`.

Example `.conf` content:

```ini
[Interface]
PrivateKey = <USER_PRIVATE_KEY>
Address = 10.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
Endpoint = <NODE_IP>:51820
PersistentKeepalive = 25
```

Import this file into WireGuard on iOS, Android, or desktop.

---

## Step 7 — Runtime user updates (no Xray restart)

When you add, modify, or remove a user in a WireGuard group:

1. The panel calls **`sync_user`** to the node (same path as VLESS/VMess).
2. The node calls Xray **HandlerService** `AddUser` / `RemoveUser` on the WireGuard inbound.
3. **Xray must be built from the UserManager patch** (see [wireguard-xray-integration.md](../../docs/wireguard-xray-integration.md) in the repo root).

Peers are **not** injected into JSON on each user change. On **node connect**, the panel sends `peers: []` and the full user list; the node applies peers via API after Xray starts.

> Legacy behaviour (10s debounce + full node reconnect) is removed. Use **node reconnect** only after changing core routing/sniffing JSON, not for ordinary user CRUD.

---

## Migration from Legacy `CoreType.wg`

If you have an existing setup with `CoreType.wg` (separate WireGuard kernel module):

1. **Generate a new Xray core** with `CoreType.xray` following Step 1 above.  
   You can reuse the same `secretKey` from your old WG core — the server public key will be identical, so existing client `.conf` files remain valid.

2. **Create a new group** linked to the `wg-in` inbound in the new Xray core.

3. **Move users** to the new group (bulk move in Dashboard → Bulk → Groups).

4. **Verify** clients connect via the new path.

5. **Delete the old `CoreType.wg` core** and disconnect the node from it.

> User WireGuard keys and `peer_ips` are fully compatible between `CoreType.wg` and `CoreType.xray` — no need to regenerate client configs.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Clients can't connect | UDP port not open | Open the WG inbound port in firewall on node |
| Traffic not routing | IP forwarding disabled | Run `sysctl net.ipv4.ip_forward=1` |
| Russian sites via proxy | Routing rules wrong | Check `geosite:category-ru` / `geoip:ru` in Xray JSON |
| New user can't connect | Node uses stock Xray | Deploy Xray build from UserManager fork; check node logs for `wireguard: applied` |
| `kernelMode` error | Missing kernel module | Set `"kernelMode": false` in inbound settings |
| Node shows error after connect | Xray version too old | Ensure Xray-core ≥ 1.8 on the node |
