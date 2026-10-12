# PKResolve

Rust workspace for Pubky resolution. See [SPEC.md](docs/SPEC.md) for the design.
The crates are stubs; networking and proof verification are not implemented.

- `pkresolve`: shared types, verification, and delegation rules.
- `client`: transport interface, resolution requests, and client cache.
- `server`: packet fetching, shared cache, and HTTP proof-bundle service.
- `reqwest`: standalone client transport adapter.

The `client` and `server` crates depend on `pkresolve`. The `reqwest` adapter
depends on `client`. The external reqwest HTTP library is not yet included;
it will use a dependency alias to avoid the local package name collision.

All packages are currently unpublished libraries. A server executable can be
added when startup and configuration are defined.

Check the workspace with:

```sh
cargo fmt --all --check
cargo check --workspace --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
```
