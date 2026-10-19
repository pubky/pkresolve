# PKResolve

Pubky endpoint resolution from signed PKARR packets, with a cached bundle
service design. See the [specification](docs/SPEC.md) for the protocol.

- [Library](pkresolve/README.md): routing, bundle processing, and client cache.
- [Server](server/src/lib.rs): PKARR provider; HTTP serving is pending.
- [Chromium](chromium/README.md): CXX integration prototype.

## Status

Unpublished prototype. PKARR 8.1 needs upstream signature and malformed-input
validation fixes before the client can safely accept untrusted bundles.

Known client cache limitations:

- Expired cached packets can still produce terminal errors, such as
  `NoCompatibleEndpoint` for an absent scoped service. Those errors do not
  trigger a fresh bundle fetch and can persist until the packet is replaced.
- Incoming packet versions are not compared with previously accepted versions.
  A delayed response can return older routes and overwrite newer cached packets.

## Development

From the repository root, with dependencies cached:

```sh
cargo fmt --all --check
cargo check --workspace --offline
cargo test --workspace --offline
cargo test --workspace --all-features --offline
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
```

Chromium has a separate [build guide](chromium/README.md#build-inside-chromium).
