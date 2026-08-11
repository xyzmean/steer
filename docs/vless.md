# VLESS/Reality Client Architecture

This document describes the VLESS/Reality client implementation available exclusively in the `steer-extended` package.

## Overview
The embedded VLESS client is designed to operate within extreme resource constraints (under 500 KB including the TLS stack), making it viable for low-end routers where standard implementations (like Xray or sing-box, which consume 20-40 MB) cannot fit. 

It handles routing, native TUN interface creation, and cryptographic handshakes directly via `mbedtls`.

## Supported Protocols
- **Transports**: `tcp`, `grpc`, `xhttp` (implemented via minimal embedded HTTP/2).
- **Security**: `reality`, `none`.
- **Flow**: `xtls-rprx-vision`, or none.
- **Traffic**: TCP over TUN.

*Note: UDP over VLESS is not supported; ICMP "Port Unreachable" is returned to trigger immediate fallback to TCP on the client side.*

## Reality Implementation Details

The Reality protocol authenticates the client using a modified TLS 1.3 handshake:
1. The server possesses a constant X25519 keypair, with the public key (`pbk`) known to the client.
2. The client generates an ephemeral keypair and places its public half in the `key_share` of the `ClientHello`.
3. A shared secret is computed from the client's ephemeral private key and the server's constant `pbk`. This secret derives an authenticator embedded in the `session_id`.
4. If the server validates the authenticator, it acts as a VLESS proxy. Otherwise, it transparently proxies the decoy site.

**Crucial Invariant**: The `ClientHello` must perfectly mimic a standard browser (e.g., Chrome). Any deviation in extension order, cipher suites, or GREASE values can be used to fingerprint the client. 

## Vision Flow

The `xtls-rprx-vision` flow obscures TLS-in-TLS characteristics by injecting randomized padding frames.
- Padding frames conceal the length of adjacent data records.
- VLESS headers are injected into the stream prior to the first Vision frame.
- Protocol symmetry dictates that the server's initial response also includes the UUID header.

## TUN Device and TCP Handling

Since `steer` processes raw IP packets but the VLESS server expects TCP streams, a lightweight TCP state machine is implemented.
- **Retransmissions**: A configurable ring buffer tracks unacknowledged bytes. Retransmissions are triggered by timeout or duplicate ACKs (RFC 5681).
- **No Reordering Buffer**: Out-of-order packets from the client are dropped and left for the client's OS to retransmit, saving router memory.
- **Multi-Threading**: Uses `IFF_MULTI_QUEUE` to allocate queues per CPU core (up to 4). Symmetric hashing ensures both halves of a TCP connection map to the same thread, eliminating the need for locks in the data path.
- **Memory Scaling**: Memory is allocated dynamically per connection (max 64 concurrent connections by default) to prevent OOM kills on memory-constrained routers.

## Connection Setup Latency

The node handshake (TCP + TLS/Reality + optional HTTP/2) costs 100-400 ms. That cost used to sit on the critical path of every new connection, because the client's `SYN-ACK` was withheld until the upstream stream was ready — a client starts its own TLS only after the handshake completes, so the delay was paid in full, per connection, on top of everything else. Plain `nftables` routing has no such step, which is exactly where the difference was felt.

Three mechanisms remove it:

- **Immediate `SYN-ACK`**: the handshake to the client completes on a local round trip, before the node stream exists. The VLESS destination address travels in the *request header* rather than at connection time, so nothing about the upstream needs to be known yet. If the stream later fails to open, the client gets an `RST` — the same outcome as before, just later.
- **Early-data buffer**: because the client is now answered immediately, its first bytes (the `ClientHello`, one to two KB) arrive while the node handshake is still running. They are held per connection, up to 8 KB, and handed to the node as soon as the stream is ready. Beyond that cap the data is simply not acknowledged, so the client retransmits it later — the same back-pressure the closed-window path already uses. Stream order is never traded for speed: fresh client data waits until the buffered tail has been delivered.
- **Spare sessions**: a small pool of pre-established node sessions (default 4, `STEER_TUN_SPARES=0` disables, max 8). The pool is refilled **only when a `SYN` arrives**, so an idle router performs no background handshakes at all; a browser opening connections in bursts finds them ready. Spares expire after 2.5 s — Xray drops a session that has not sent a VLESS request within its handshake timeout (4 s by default) — and expired ones are closed by a once-per-second sweep so an idle pool does not hold sockets or TLS buffers indefinitely.

Measured on a MediaTek Filogic router against a real Reality node, fetching `www.youtube.com` through the tunnel (median of 6 fresh connections):

| | TCP connect | TTFB |
|---|---|---|
| before | 147 ms | 370 ms |
| after | 0 ms | 242 ms |
| burst of 6, before | 183 ms | 410 ms |
| burst of 6, after | 1 ms | 252 ms |

Throughput and CPU per megabyte are unchanged (1.0 ms/MB on the local rig before and after); this work targets latency only.

## Exit Codes

`steer vless <output>` always exits with a **non-zero code (`1`)** when the tunnel process returns at all, and emits a single reason line to the journal (`steer[warn]` prefix). The exit code is `1` on every terminating path — a clean `0` would be a lie here, because the process only ends when the tunnel is no longer carrying traffic. procd / the control plane should treat non-zero as "tunnel is down" and read the reason line for the cause.

Previous versions returned `-40` / `-41` from `tun_open`, which `main` truncated to bytes `216` / `215` — numbers meaningless to both humans and the control plane. These are now unified to `1` with a named reason.

| Exit | Reason (journal line) | Cause |
|------|-----------------------|-------|
| `1`  | `steer[warn] tunnel: нет /dev/net/tun (...) — не установлен kmod-tun` | `/dev/net/tun` missing — the `kmod-tun` package is not installed. |
| `1`  | `steer[warn] tunnel: устройство <dev> не создалось: ... (отказал TUNSETIFF)` | The TUN device could not be created (`TUNSETIFF` failed, or `/dev/net/tun` would not open). |
| `1`  | `steer[warn] tunnel: <dev> не поднялся ни одной очередью из <N>` | No worker queue was ever established before the process ended. |
| `1`  | `steer[warn] tunnel: <dev> больше не несёт трафик — все очереди (<N>) завершились` | The tunnel ran, but all queues have now drained/ended, so the tunnel is no longer serving traffic. |

A control plane restarting the tunnel on non-zero exit should distinguish the `kmod-tun` / device-creation failures (infrastructure problem, restart won't help) from the "queues ended" case (transient, restart may recover).
