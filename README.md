# Steer: Policy-Based Routing Engine for OpenWrt

Steer is a high-performance, declarative policy-based routing engine designed specifically for OpenWrt. It translates declarative JSON specifications into `nftables` rules, routing tables, and IP sets atomically.

Steer is built with strict resource constraints in mind, optimized for the lower bounds of home routers (single core, limited memory). It acts purely as a routing engine: it does not download lists or provide a Web UI. For a complete solution with a UI and automatic list updates, see [splify2](https://github.com/xyzmean/splify2).

[![Telegram](https://img.shields.io/badge/Telegram-chat-2CA5E0?style=flat&logo=telegram)](https://t.me/ssplify)
[![Support Project](https://img.shields.io/badge/Support-project-f5365c?style=flat)](https://www.donationalerts.com/r/yo1nkxxd)

## Features
- **Declarative Configuration:** Define exactly what traffic goes where using a simple JSON file.
- **Resource Efficiency:** Designed to run on weak hardware. Uses `nftables` sets loaded in a single transaction.
- **Advanced DNS Handling:** Built-in `dnsd` resolver for domain-based routing with `fake-ip` (default) and `real-ip` modes.
- **Failover:** Automatic fallback between multiple interfaces (e.g., VPN tunnels) with priority support.
- **VLESS/Reality Support:** First-class support for VLESS/Reality via the `steer-extended` package, with native TUN integration. Carries both TCP and UDP, so QUIC/HTTP-3, WireGuard/WARP and game traffic work through a VLESS output.
- **Memory Fitter:** Automatically fits large IP lists (like national blocklists) into router memory using density-based aggregation (`steer fit`).

## Installation

Download the pre-compiled `.apk` packages for your architecture from the [Releases](https://github.com/xyzmean/steer/releases) page. The architecture in the filename matches `DISTRIB_ARCH` from `/etc/openwrt_release`.

```sh
# For basic routing
apk add --allow-untrusted ./steer-<version>-1_<arch>.apk

# Or for VLESS/Reality support
apk add --allow-untrusted ./steer-extended-<version>-1_<arch>.apk
```
*Note: `steer-extended` acts as a drop-in replacement and provides all base features plus VLESS/Reality support.*

## Configuration (spec.json)

Steer is configured via a JSON specification file (typically `/etc/steer/spec.json`). The engine reads this file to determine traffic channels and output interfaces. 

### Example Configuration

```json
{
  "schema": 1,
  "lan_device": "br-lan",
  "from_default": ["192.168.1.0/24"],
  "outputs": {
    "vpn": {
      "kind": "interface",
      "devices": ["awg0", "wg0"],
      "on_fail": "drop"
    },
    "vless_out": {
      "kind": "vless",
      "sub_file": "/etc/steer/sub.txt",
      "on_fail": "zapret"
    },
    "direct": {
      "kind": "direct"
    }
  },
  "channels": [
    {
      "name": "geoblock",
      "match": { "domains_files": ["/etc/steer/lists/geo.lst"] },
      "out": "vpn"
    },
    {
      "name": "blocked_ips",
      "match": { "prefixes_files": ["/etc/steer/lists/ipsum.lst"] },
      "out": "vless_out"
    },
    {
      "name": "smart_tv",
      "from": ["192.168.1.50"],
      "match": { "any": true, "allow_all": true },
      "out": "direct"
    }
  ]
}
```

### JSON Fields Explained

- **`schema`**: Configuration schema version (must be `1`).
- **`lan_device`**: The local network interface (e.g., `br-lan`).
- **`from_default`**: The default source subnet(s) to apply rules to if a channel doesn't specify one.

#### `outputs`
Defines the destination routing interfaces.
- **`kind`**: Type of output (`interface`, `vless`, or `direct`).
- **`devices` / `device`**: Network interface names (e.g., `wg0`, `tun0`). If an array is provided, it acts as a priority list for failover.
- **`on_fail`**: Action to take if all devices in the output are down.
  - `drop` (default): Block traffic (blackhole) to prevent leaks.
  - `direct`: Route traffic directly without VPN.
  - `zapret`: Route directly, but verify that a DPI bypass (zapret) is running.
- **`sub_file`**: (VLESS only) Path to the subscription file.

#### `channels`
Defines routing policies. Evaluated in order (top to bottom). The first match wins.
- **`name`**: Channel identifier.
- **`from`**: (Optional) Source IP or MAC addresses. All entries must be the **same type** — a `from` array may contain IPs **or** MACs, but mixing the two is rejected (e.g., `["192.168.1.50", "192.168.1.51"]` or `["00:11:22:33:44:55"]`). To route both a host and a MAC, define two channels.
- **`enabled`**: (Optional, default `true`) Set to `false` to keep a channel in the spec without installing any rules — it generates no nft set and no chain entry, and is skipped by sanity checks. Handy for temporarily disabling a broken rule without deleting it.
- **`out`**: The name of the output (defined in `outputs`) where matched traffic should go.
- **`match`**: Conditions for the traffic:
  - **`domains_files`**: Array of file paths containing domains to match. Uses the built-in `dnsd` resolver.
  - **`prefixes_files`**: Array of file paths containing IP subnets (CIDR) to match.
  - **`mode`**: DNS resolution mode for domain lists. `fakeip` (default, highly accurate) or `realip`.
  - **`any`** / **`allow_all`**: Use `true` to match all traffic from the specified source.

## Command Line Interface

- `steer apply [--dry-run]` — Compiles the JSON spec into active `nftables` rules and routing tables.
- `steer status` — Outputs the current applied state in JSON format.
- `steer diag` — Runs diagnostics and reports the health of the engine (exits with `1` if broken).
- `steer explain <ip|domain>` — Explains exactly which channel and output a given address or domain will use.
- `steer fit --budget N <file>` — Aggregates and trims an IP list to fit within `N` memory elements.
- `steer failover` — Checks output health and updates active interfaces based on priority.

### Log levels (journal contract)

steer writes diagnostics to the system journal (stderr). Each line carries a stable prefix that names its severity — this prefix is the parseable contract, since the prose wording may change between releases:

- `steer[warn]` — a real concern: something is broken or routing traffic the wrong way.
- `steer[info]` — informational status, not an alarm.

A control plane (e.g., splify2) should classify a line by this prefix rather than by its text. The prefix appears before a subsystem label (for example, `steer[warn] tunnel: ...`).

## Building from Source

Steer is written in C and uses Zig as a cross-compiler to build static musl binaries for all architectures.

```sh
make                      # Native build for development
make test                 # Run offline unit tests
./build.sh                # Build static binaries and APKs for all architectures using Docker
```

## Documentation

For deep technical details on the Steer architecture:
- [contract-v1.md](docs/contract-v1.md): Specification format, state format, invariants.
- [vless.md](docs/vless.md): Architecture of the integrated VLESS/Reality client.

---
*If you need a complete UI and automated lists, consider using [splify2](https://github.com/xyzmean/splify2).*
