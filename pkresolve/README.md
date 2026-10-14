# pkresolve

`pkresolve::Client` owns the packet cache and bundle processing.
Call `prepare(request)` to obtain cached endpoints or a `BundleRequest`.
Send its JSON body to `/v1/resolve` using your HTTP stack, then pass the retained
request and response bytes to `accept_bundle()`. Failed bundles leave the cache
unchanged; packets retain their native `last_seen`.

See the [prototype limits](../README.md#status).

Derive Pubky endpoints from a `PacketProvider`, without an HTTP stack or async
runtime:

```rust
let resolution = pkresolve::resolve(&request, &provider).await?;
```

Providers supply valid `Arc<SignedPacket>` values and own validation, caching,
and proof collection. Each key must return the same packet version throughout
one resolution. A `HashMap<PublicKey, Arc<SignedPacket>>` implements the trait.

Supports same-name HTTPS ServiceMode, multiple endpoints, signed addresses and
hints, HTTP/1.1, and HTTP/2. Aliases and TLS delegation are deferred. See the
[specification](../docs/SPEC.md) for scope and protocol details.

Use `resolution.service` as TLS SNI and require its raw public key for every
candidate. Preserve the original HTTP authority. Check `resolution.expires_at`
before reuse; it follows the packet's shortest TTL, aged from `last_seen`.

Run the direct ServiceMode example from the repository root:

```sh
cargo run -p pkresolve --example resolve --offline
```
