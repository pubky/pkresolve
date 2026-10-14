# pkresolve

Protocol core for Pubky resolution, without network I/O or an async runtime.
See [the specification](../docs/SPEC.md) for the proposed protocol.

## Usage

1. Construct a `ResolutionRequest` with an exact `ServiceName`, original URL
   port, and supported HTTP protocols.
2. Supply `PacketProof` values containing full signed PKARR bytes and each
   packet's unsigned `last_seen` observation time.
3. Call `verify_packets` with your freshness policy, paired wall and monotonic
   clocks, and previously accepted packet versions.
4. Call `derive_resolution` with those verified packets and the original
   request. It returns all compatible candidates or an error.
5. Retain the verified packet versions for rollback protection and use the
   resolution's dependencies to invalidate cached results after updates.

Run the local signed-packet example:

```sh
cargo run -p pkresolve --example resolve --offline
```

The host schedules endpoints by priority, shuffles equal priorities, and opens
connections. Every TLS attempt must prove possession of its candidate's raw
Ed25519 authority key. Preserve the original URL, HTTP authority, and SNI.
A verified resolution establishes policy; it does not authenticate a peer.

## Supported behavior

- Same-name HTTPS ServiceMode records, including multiple priorities and ports.
- Signed A/AAAA addresses and IPv4/IPv6 hints, with deduplication.
- HTTP/1.1 and HTTP/2 ALPN compatibility, including mandatory parameters.
- Direct raw-key TLS and bounded, port-preserving Pubky TLS CNAME chains.
- Exact service scope, signature verification, missing-proof errors, cycle
  checks, and packet, byte, record, hop, and candidate limits.
- TTL aging from `last_seen`, bounded signed-packet age, and monotonic reuse
  deadlines. Terminal packets also bound the lifetime of absent TLS CNAMEs.
- Rollback and equal-timestamp conflict checks against caller-retained history.

Routing CNAMEs, HTTPS aliases, alternate targets, ICANN CA delegation, X.509
credentials, HTTP/3, and ECH are not supported yet. Unsupported mandatory
parameters skip a candidate; optional unknown parameters and ECH are ignored.
Missing compatible service records never enable bare-address fallback.
Malformed records and incomplete proofs fail the whole resolution.

Wire checks reject ambiguous/non-ASCII DNS labels, compression loops, trailing
DNS data, and malformed service parameters before the DNS dependency parses
packets. Only answer records in the signer's namespace authorize resolution.

## Cache contract

Use the earliest candidate deadline when caching a complete resolution. Expired
nonzero record TTLs are rejected; TTL zero produces a transaction-only result.
`last_seen` is unsigned and cannot extend the signed-packet freshness allowance.
Neither field proves the packet is the newest published version.

Retain `PacketVersion` entries beyond cache expiry. Starting with empty history
loses protection against previously seen versions. This crate performs no disk
persistence, packet fetching, connection invalidation, or TLS handshakes.
The client and host own those responsibilities.

The HTTP schema, JSON/base64 conversion, timestamp text parsing, and transport
size/time limits belong to adapters; the core currently accepts typed inputs.
