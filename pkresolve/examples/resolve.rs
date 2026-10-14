//! Resolve a locally signed proof bundle without network I/O.

use std::{collections::HashMap, sync::Arc};

use pkarr::{Keypair, SignedPacket, dns::Name, dns::rdata::SVCB};
use pkresolve::{HttpProtocol, ResolutionRequest, derive_resolution};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::random();
    let root_label = Name::new_unchecked(".");
    let packet = SignedPacket::builder()
        .https(root_label.clone(), SVCB::new(1, root_label.clone()), 60)
        .address(root_label, "203.0.113.10".parse()?, 60)
        .sign(&keypair)?;
    let provider = HashMap::from([(keypair.public_key(), Arc::new(packet))]);
    let request =
        ResolutionRequest::new(keypair.to_z32().parse()?, 443, vec![HttpProtocol::Http11])?;
    let result = futures_lite::future::block_on(derive_resolution(&request, &provider))?;
    for candidate in &result.candidates {
        println!(
            "{}:{}; SNI {}; required raw TLS key {}",
            candidate.addresses[0],
            candidate.port.get(),
            result.service,
            result.service.public_key(),
        );
    }
    Ok(())
}
