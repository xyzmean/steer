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
- **`obfs`**: (Optional, `kind: interface` only.) Carries the tunnel's UDP transport inside a fake
  TCP stream — WireGuard over TCP, wire-compatible with phantun. Adds 12 bytes of overhead
  (a 20-byte TCP header instead of an 8-byte UDP one) and keeps datagram semantics: no
  retransmission, no flow control, one datagram per segment. Present on both the base and the
  extended package.
  ```json
  "vpn": {
    "kind": "interface", "device": "wg0", "on_fail": "drop",
    "obfs": { "mode": "wg-over-tcp",
              "server": "203.0.113.10:4567",
              "listen": "127.0.0.1:51820" }
  }
  ```
  - **`mode`**: (Optional.) Only `wg-over-tcp` exists today; an absent value means it. An unknown
    value is rejected rather than assumed.
  - **`server`**: Address and port of the obfuscation server (`steer obfs-server` or upstream
    `phantun_server`). Must be a literal IPv4 address, not a hostname: resolving a name would
    mean asking DNS, which may itself be routed through the tunnel this server is bringing up.
    The control plane resolves it and writes the address.
  - **`listen`**: Local address and port the obfuscator listens on. It must equal the peer's
    `Endpoint` in `/etc/config/network` — this is the one place where two configurations must
    agree, and the engine cannot derive one from the other because WireGuard keys and peers are
    not its property. A mismatch is silent: WireGuard sends into nowhere.
  - **MTU**: the tunnel interface MTU must not exceed `link_mtu − 72` (outer IP 20 + fake TCP 20 +
    WireGuard 32) — 1428 on a 1500-byte link, 1420 on PPPoE. Both ends of the tunnel must use the
    same MTU. `steer diag` computes the limit from the actual egress device and warns with the
    exact number.
  - Enumerated by `steer outputs --obfs`; run by `steer obfs <output>` (a procd instance named
    `obfs_<output>`). The process installs one nft rule of its own, in table `inet steer_obfs`,
    which drops the kernel's RST for its own flow — without it the router's own stack tears down
    the session. The rule lives outside `inet steer` because `apply` rebuilds that table whole.

### Channels
Defines routing rules. The array order dictates the priority (first match wins).
- **`name`**: Identifier for the channel.
- **`enabled`**: (Optional, default `true`). When `false`, the channel stays in the spec but installs no nft set and no chain rule, and is skipped by the sanity checks. Use this to keep a rule on file while disabling it.
- **`from`**: Array of source IP **or** MAC addresses. All entries in one array must be the same type — mixing IP and MAC addresses in a single `from` array is rejected with an error, because nft cannot express "IP or MAC" inside one rule. To match both a host and a MAC, define separate channels.
- **`match`**: Object containing conditions:
  - **`domains_files`** / **`domains_file`**: Paths to domain lists. A channel may combine `domains_files` and `prefixes_files` (address + domain matching in one channel is supported).
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
    { "name": "vpn_dom", "out": "vpn", "kind": "domains", "live": true, "packets": 5009, "bytes": 1799237, "down_packets": 4120, "down_bytes": 5981023, "lists": 2, "channels": ["youtube", "google"] }
  ]
}
```
- **`channels`**: In the output, these represent merged groups (channels sharing the same output and matching criteria), not the original 1-to-1 spec channels.
- **`live`**: `false` means the rule is missing from the kernel.
- **`packets` / `bytes`**: Outbound (upload) counters — packets leaving the router toward the output. `bytes` deliberately keeps this "outbound" meaning for backward compatibility with installed control planes.
- **`down_packets` / `down_bytes`**: Inbound (download) counters, counted on the `postrouting_down` chain. Emitted only when the channel carries download traffic. Do not repurpose `bytes` for download — existing UIs read it as upload.
- **`lists`**: Number of source list files backing this merged group.
- **`in_firewall` / `nat`**: Diagnostic flags indicating if the tunnel is correctly configured in the OpenWrt firewall.
- **`obfs`**: Present only when the output carries its transport over fake TCP. Mirrors the spec —
  `{ "mode": "wg-over-tcp", "server": "203.0.113.10:4567", "listen": "127.0.0.1:51820" }`. It
  deliberately carries **no liveness flag**: `status` is polled every few seconds and checking a
  process means spawning one. The verdict on whether the obfuscator is running belongs to `diag`,
  which is asked on demand.

## 3. Input Limits and Validation

The specification is strict JSON. Inputs that violate these rules cause `steer` to refuse the spec (exit non-zero) rather than proceed with a silently broken state.

- **Strict JSON, no trailing comma**: arrays like `[...,]` are rejected. Use standard JSON. (Previously a trailing comma could hang the parser; it now fails loudly.)
- **File size**: the spec file must be **≤ 256 KiB**. A larger file is rejected (`spec too large (max 256 KiB)`) rather than silently truncated.
- **Array sizes** (overflow is rejected, not silently dropped):
  - `domains_files` / `prefixes_files`: ≤ 16 entries each.
  - `from` / `from_default`: ≤ 16 entries.
  - `outputs.*.devices`: ≤ 8 entries.
  - `outputs`: ≤ 16. `channels`: ≤ 64.
- **String length**: each `from`/`devices` entry is capped at its documented width (256 / 64 / 32 bytes respectively).

These caps exist to fit the fixed memory budget of low-end routers. A control plane assembling large specs should keep within them.

## 4. Diagnostics (Output)

Requested via `steer diag [--spec FILE]`. Runs a set of health checks and emits JSON:

```json
{
  "schema": 1,
  "checks": [
    { "id": "table", "verdict": "ok", "what": "nft-таблица steer на месте", "why": "" }
  ],
  "warn": 0,
  "fail": 0
}
```

- Each check object has `id`, `verdict`, `what`, `why`.
- **Verdicts** are one of four values:
  - `ok` — checked and good.
  - `note` — advice, not a finding: it works and will keep working, but is worth knowing. **`note` is deliberately excluded from the `warn`/`fail` counters** and must not be treated as "not ok". (Without this, always-true advice — e.g. a browser with DoH bypassing the router's DNS — would permanently paint a healthy router red.)
  - `warn` — it works, but there is something that explains a likely future complaint.
  - `fail` — broken; traffic is going the wrong way.
- **Check `id`s** currently emitted: `table`, `down_chain`, `set`, `dns_redirect`, `dnsd`, `doh`, `ipv6`, `resolver`, `output`, `obfs`. The set may grow *and shrink* between releases; consumers must tolerate unknown ids and must not require any particular id to be present.
  - `udp` — **no longer emitted.** It used to be a `note` saying the VLESS tunnel carries TCP only. The tunnel now carries UDP (VLESS command 2), so QUIC, WireGuard and game traffic work through a `kind: vless` output. A consumer that treated the absence of this note as "old version" must instead read the version.
  - `obfs` — emitted per output that has an `obfs` block, up to four times: the obfuscator process
    is running (`fail` if not); its anti-RST rule is installed (`warn` if not — without it the
    router's own kernel tears the session down); the route to the obfuscation server does **not**
    go through the tunnel that server brings up (`fail` — that loop cannot be broken from inside);
    and the tunnel MTU fits inside the fake TCP envelope (`warn`, with the exact number to set).
  - `resolver` — emitted as a `note` when a `kind: vless` channel's address list contains a public resolver (for example `8.8.8.0/24` inside a Google or YouTube category). Such DNS queries do reach the resolver through the tunnel, but each query is a fresh UDP flow and therefore a fresh handshake to the node: names resolve, only slower. Never a `warn` — nothing is broken.
- **Exit code**: `steer diag` exits `1` only when at least one check is `fail`; `note` and `warn` never cause a non-zero exit.
- **Top-level counters**: `warn` = number of `warn` verdicts; `fail` = number of `fail` verdicts. There is no `note` counter.

## 5. Log Prefixes (Journal Contract)

steer logs to the journal (stderr) with a fixed severity prefix on every line. This prefix — not the prose wording — is the contract a control plane should classify by, because the wording may change between releases:

- `steer[warn]` — a real concern (something broken or mis-routed).
- `steer[info]` — informational status, not an alarm.

A subsystem label follows the prefix (e.g. `steer[warn] tunnel: ...`). Parse the prefix to decide severity.

## 6. Architecture Invariants
- **First Match Wins**: Rules are evaluated top-to-bottom.
- **File-Based Matching**: Matches rely strictly on external file paths to conserve memory.
- **Stateless Configuration**: Dynamic changes (like failover) update the routing tables directly without modifying the core nftables ruleset.
- **Marking Strategy**: Packet marks are applied in `prerouting mangle` before routing decisions are finalized.
