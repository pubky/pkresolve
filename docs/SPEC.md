# PKResolve: high-level specification

Status: draft for review; implementation and deployment are separate decisions.

## Purpose

PKResolve resolves public-key service names into verified endpoint candidates.
The service follows delegation chains and caches signed PKARR packets. It
returns those packets in one HTTP response; the Rust client verifies them and
builds the candidates locally.

The shared service cache should reduce lookup round trips and latency.
Chromium still opens connections, authenticates TLS, and sends HTTP requests.

```text
Chromium → Rust client → PKResolve service → packet cache / PKARR sources
                      ← signed packets with last_seen
         ← verified endpoint candidates
Chromium → selected endpoint → TLS authentication
```

The design follows the [routing and TLS delegation proposal][delegation]:
routing records choose where to connect; separate TLS delegation records
choose who may authenticate the server.

## Initial scope

Recommended first implementation:

- One complete response; no streaming.
- Same-name HTTPS ServiceMode routing with multiple endpoints and ports.
- Direct raw-key TLS and bounded TLS CNAME chains between Pubky names.
- HTTP/1.1 and HTTP/2.

Require a compatible ServiceMode record before using addresses. Missing or
incompatible service records must not trigger bare-address fallback. This is
stricter than the current fork, which uses DoH and checks the raw TLS key
against the URL key without verifying PKARR delegation.

Later stages can add HTTPS aliases, alternate targets, Pubky-signed
certificates, and explicit ICANN CA delegation. Combined hostname CNAME
routing and TLS delegation still needs a protocol rule.

## Components

- `pkresolve`: shared types, packet verification, delegation rules, and
  candidate derivation; independent of an HTTP runtime.
- `client`: transport interface, requests, and verified-result cache.
- `server`: packet fetching, shared caches, and proof-bundle assembly.
- `reqwest`: optional transport for standalone clients.
- `net/pubky/`: Chromium adapter using Rust, CXX, and Chromium networking.

Server and client share interpretation code. The server discovers required
packets; the client independently verifies them and derives the result.

## HTTP API

Send `POST /v1/resolve` over HTTPS. Names below are placeholders for canonical
public-key names. The wire schema and packet encoding remain provisional.

```json
{
  "service": "alice-key",
  "url_port": 443,
  "supported_alpn": ["h2", "http/1.1"],
  "allowed_authentication": ["pubky_raw_key"]
}
```

`service` preserves the full name: `alice-key`, `app.alice-key`, and
`_pubky.alice-key` are distinct services. `url_port` is the original port,
which can differ from the connection port selected by routing records.

Capabilities tell the server which branches need packets. The client retains
and independently enforces its policy; unknown authentication modes must fail.
Requests omit application paths, queries, cookies, and credentials.

Return each required packet once, with its observation time:

```json
{
  "schema": 1,
  "packets": [
    {
      "key": "alice-key",
      "signed_packet": "<base64 signed packet>",
      "last_seen": "2026-10-12T12:00:00Z"
    },
    {
      "key": "provider-key",
      "signed_packet": "<base64 signed packet>",
      "last_seen": "2026-10-12T11:59:30Z"
    }
  ]
}
```

The response contains complete signed packets, including those establishing
that TLS delegation ends. Candidates and TLS policies are derived locally.

`last_seen` is when the service last retrieved and verified that exact packet
version from a source, in UTC `YYYY-MM-DDTHH:MM:SSZ` format. A new source fetch
can advance it; reading a local cache or serving a response cannot. It is
unsigned service metadata, distinct from the packet's signed timestamp. The
source may itself serve cached data.

Return typed errors for invalid requests, unsupported capabilities, missing
packets, invalid records, limits, and timeouts. Distinguish incomplete lookup
from no compatible endpoint. A partial bundle cannot count as success, and a
server error cannot prove nonexistence or authorize weaker authentication.

## Client verification and output

Before returning candidates, the client must:

1. Bound response size and parsing work; verify packet signatures with the
   PKARR library. Reject conflicting versions in one bundle.
2. Enforce freshness and reject versions older than previously accepted ones.
3. Follow routing and TLS chains from the original request, enforcing
   namespace and service scope, record rules, cycle checks, and lookup limits.
4. Resolve TLS authority separately for each connection port at
   `_<port>._tcp.<original-service>`. Routing grants no TLS authority.
5. Derive all compatible candidates from the records. Missing required packets
   fail as incomplete proof; response order grants no priority.

The result is a `VerifiedResolution`: endpoint candidates plus a bounded reuse
deadline. Each candidate keeps its addresses, port, priority, ALPN, supported
ECH settings, and authentication policy together. Only verification and
derivation can construct this result. It does not establish peer identity
until the TLS handshake succeeds.

Preserve the original URL, HTTP authority, and, for Pubky TLS, SNI. Authenticate
against the verified authority key. Prefer lower service priorities and apply
the protocol's selection rules within equal priorities. Every attempt retains
its candidate's policy; authentication failure never enables CA fallback.
HTTP request replay remains the application's responsibility.

## Caching

The server caches packets by key, version, and `last_seen`. Cached bundles
track their packet dependencies and request capabilities. New packet versions
invalidate affected bundles; concurrent missing-packet requests share a fetch.

For each relevant record, the client computes:

```text
observed_age = max(0, client_now - last_seen)
remaining_ttl = max(0, record_ttl - observed_age)
```

Cap reuse by local cache limits and the remaining signed-packet freshness
allowance. Use the earliest deadline across all dependencies. Reject malformed
or excessively future `last_seen` values, allow bounded clock skew, and store
accepted deadlines using a monotonic clock.

Repeated responses cannot reset signed-packet age. A newer `last_seen` may
refresh a TTL within local limits, but cannot bypass replay checks. Neither
signatures nor observation times prove that a packet is the newest version.
Withdrawal guarantees therefore depend on the freshness policy.

Observed authorization changes invalidate affected connections and resumption
state. Keep early data and raw-key resumption disabled initially.

## Rust API and Chromium integration

Proposed interface boundaries:

```text
ResolutionTransport::resolve(request, context) -> untrusted proof bundle bytes
Client::resolve(request, context) -> VerifiedResolution
```

The context supplies cancellation, deadlines, and size limits. Enforce size
limits during download and again before parsing. Application policy selects
the service URL. Adapters share a timeout, redirect, and cancellation contract.

In Chromium, a Rust wrapper implements the transport through CXX callbacks to
Chromium's network service. Call the client from host resolution and translate
its results into endpoint metadata, carrying TLS authority and lifetime through
caches and IPC. The TLS socket consumes that authority instead of always
extracting its expected key from the URL.

Use Chromium's proxy and certificate policies, profile isolation, endpoint
scheduler, HTTP stack, and BoringSSL. Bootstrap the service hostname through
ordinary HTTPS/DNS. Standalone clients can use the `reqwest` adapter.

Keep different Pubky origins isolated even when they share a provider key.
Connection reuse must respect service identity and current authorization;
keep cross-origin pooling and HTTP/3 disabled initially.

## Extensions and open decisions

- **ICANN routing:** Chromium resolves target addresses under its DNS policy.
  Ordinary DNS answers are outside PKARR proofs. Following HTTPS aliases into
  ICANN DNS needs an explicit continuation policy.
- **Pubky certificates:** specify signer, reference-name, validity, and
  certificate-profile checks independently of SNI.
- **CA delegation:** require signed permission and local policy before using
  the delegated hostname for SNI and ordinary CA verification.
- **CA endpoint declarations:** expose a separate application endpoint; they
  do not transfer Pubky-origin cookies or preserve that browser origin.

Before implementation, settle the protocol revision, encoding, error mapping,
resource limits, freshness and clock rules, timestamp conflicts, persistence,
and connection lifetime. Define service selection and logging/retention policy:
the service sees requested names.

Validate forged and incomplete proofs, delegation scope, endpoint priorities,
TLS key mismatch, cache aging and invalidation, limits, cancellation, and
Chromium isolation. Compare cold and warm service latency with local packet
traversal before claiming a performance improvement.

[delegation]: https://github.com/pubky/pkdns/blob/research/delegation/research-delegation/05-routing-and-tls-delegation.md
