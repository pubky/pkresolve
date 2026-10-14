//! Pubky routing and direct raw-key TLS with pluggable packet sources.
//!
//! Use [`Client`] for cache-first resolution and whole-bundle processing.
//! The caller supplies HTTP; the library performs no network I/O.
//!
//! Call [`derive_resolution`] (also exported as [`resolve`]) with a
//! [`PacketProvider`] backed by PKARR, a local cache, or a response bundle.
//! Missing evidence is never a negative answer.
//! The host authenticates every candidate with `Resolution::service.public_key()`
//! and uses that service name as TLS SNI.
//!
//! Supports same-name HTTPS ServiceMode records and direct raw-key TLS using
//! the destination Pubky key. TLS delegation records are ignored. HTTPS aliases,
//! routing CNAMEs, alternate targets, CA TLS, certificates, ECH, and HTTP/3 are
//! not implemented.

pub mod client;
mod error;
mod name;
mod provider;
mod resolution;

pub use client::Client;
pub use error::Error;
pub use name::ServiceName;
pub use pkarr::{PublicKey, SignedPacket};
pub use provider::PacketProvider;
pub use resolution::derive_resolution as resolve;
pub use resolution::{
    EndpointCandidate, HttpProtocol, Resolution, ResolutionRequest, derive_resolution,
};
