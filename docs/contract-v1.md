# Steer Contract (Schema 1)

This document describes the interface between the control plane (e.g., [splify2](https://github.com/xyzmean/splify2)) and the steer routing engine. 

The configuration format is JSON. JSON was chosen because it is natively supported by OpenWrt (`jsonfilter`, `blobmsg`, LuCI) and preserves array ordering, which is semantically significant for steer channels. Unknown keys in the specification are silently ignored to ensure forward compatibility.

## 1. Specification (Input)

The specification file is typically located at `/etc/steer/spec.json`.

```json
{
  "schema": 1,
  "lan_device": "br-lan",
  "from_default": ["192.168.1.0/24"],
  "outputs": {
    "vpn": { "kind": "interface", "devices": ["awg0", "wg0"], "on_fail": "drop" },
    "direct": { "kind": "direct" }
  },
  "channels": [
    { "name": "geoblock", "match": { "domains_files": ["/etc/steer/lists/geo.lst"] }, "out": "vpn" }
  ]
}
```

### Global Configuration
- **`schema`**: Must be `1`.
- **`lan_device`**: The internal network interface (e.g., `br-lan`). Needed for DNS redirection.
- **`from_default`**: Subnets applied to channels that do not explicitly specify a `from` array.

### Outputs
Defines the destination routing interfaces.
- **`kind`**: Type of output (`interface`, `vless`, or `direct`).
- **`devices` / `device`**: Interface name(s). If an array is used, it defines the failover priority order.
- **`on_fail`**: Action if all interfaces fail. Options: `drop` (default, blackhole to prevent leaks), `direct`, `zapret`.

### Channels
Defines routing rules. The array order dictates the priority (first match wins).
- **`name`**: Identifier for the channel.
- **`from`**: Array of source IP or MAC addresses.
- **`match`**: Object containing conditions:
  - **`domains_files`** / **`domains_file`**: Paths to domain lists.
  - **`prefixes_files`** / **`prefixes_file`**: Paths to IP lists.
  - **`mode`**: DNS mode for domain channels. `fakeip` (issues addresses from `198.18.0.0/15`, default) or `realip`.
  - **`any`** & **`allow_all`**: Must both be `true` to match all traffic from the specified sources.
- **`out`**: The target output name.

## 2. State (Output)

Requested via `steer status`. Returns the currently applied configuration and live states.

```json
{
  "schema": 1,
  "outputs": {
    "vpn": { "kind": "interface", "device": "awg0", "up": true, "mark": "0x00100000", "table": 300, "in_firewall": true, "nat": true }
  },
  "channels": [
    { "name": "vpn_dom", "out": "vpn", "kind": "domains", "live": true, "packets": 5009, "bytes": 1799237, "channels": ["youtube", "google"] }
  ]
}
```
- **`channels`**: In the output, these represent merged groups (channels sharing the same output and matching criteria), not the original 1-to-1 spec channels.
- **`live`**: `false` means the rule is missing from the kernel.
- **`in_firewall` / `nat`**: Diagnostic flags indicating if the tunnel is correctly configured in the OpenWrt firewall.

## 3. Architecture Invariants
- **First Match Wins**: Rules are evaluated top-to-bottom.
- **File-Based Matching**: Matches rely strictly on external file paths to conserve memory.
- **Stateless Configuration**: Dynamic changes (like failover) update the routing tables directly without modifying the core nftables ruleset.
- **Marking Strategy**: Packet marks are applied in `prerouting mangle` before routing decisions are finalized.
