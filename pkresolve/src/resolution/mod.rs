//! Pubky service resolution with synchronous and asynchronous packet providers.

mod drivers;
mod https;
mod routing;
mod traversal;
mod types;

pub use drivers::{derive_resolution, derive_resolution_async};
pub use types::{EndpointCandidate, HttpProtocol, Resolution, ResolutionRequest};
