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
