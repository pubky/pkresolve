use std::{
    collections::HashSet,
    net::IpAddr,
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};

use pkarr::dns::{
    Name, ResourceRecord,
    rdata::{RData, SVCB, SVCParam},
};

use crate::{Error, PacketProvider, ServiceName, SignedPacket};

/// Supported TCP HTTP application protocols. HTTP/3 needs a separate policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpProtocol {
    /// HTTP/1.1; the default HTTPS protocol when defaults are allowed.
    Http11,
    /// HTTP/2 over TLS.
    Http2,
}

impl HttpProtocol {
    /// TLS ALPN identifier.
    pub fn alpn(self) -> &'static str {
        match self {
            Self::Http11 => "http/1.1",
            Self::Http2 => "h2",
        }
    }
}

/// Original service scope and client-supported protocols.
/// Raw-key Pubky authentication is the only supported authentication mode.
#[derive(Clone, Debug)]
pub struct ResolutionRequest {
    service: ServiceName,
    url_port: NonZeroU16,
    supported_protocols: Vec<HttpProtocol>,
}

impl ResolutionRequest {
    /// Construct a request preserving the original port and full service name.
    ///
    /// # Errors
    /// Rejects port zero and an empty protocol list.
    pub fn new(
        service: ServiceName,
        url_port: u16,
        supported_protocols: Vec<HttpProtocol>,
    ) -> Result<Self, Error> {
        let url_port =
            NonZeroU16::new(url_port).ok_or(Error::InvalidRequest("URL port must be nonzero"))?;
        if supported_protocols.is_empty() {
            return Err(Error::InvalidRequest(
                "at least one HTTP protocol is required",
            ));
        }
        Ok(Self {
            service,
            url_port,
            supported_protocols,
        })
    }
    /// Original scoped service name, also retained as SNI and HTTP host.
    pub fn service(&self) -> &ServiceName {
        &self.service
    }
    /// Original URL port, independent of a candidate's connection port.
    pub fn url_port(&self) -> u16 {
        self.url_port.get()
    }
    /// Protocols in client preference order.
    pub fn supported_protocols(&self) -> &[HttpProtocol] {
        &self.supported_protocols
    }
}

/// One compatible route, authenticated with the destination Pubky key.
#[derive(Clone, Debug)]
pub struct EndpointCandidate {
    /// Signed addresses and hints, deduplicated. The host chooses address order.
    pub addresses: Vec<IpAddr>,
    /// Selected connection port; it does not change the URL or HTTP authority.
    pub port: NonZeroU16,
    /// Lower values are preferred; callers shuffle equal-priority candidates.
    pub priority: u16,
    /// Compatible ALPNs in client preference order.
    pub protocols: Vec<HttpProtocol>,
}

/// Routes sharing the destination service's raw TLS key and a reuse deadline.
/// This describes how to authenticate a peer; it does not establish TLS identity.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// Original service for HTTP authority and TLS SNI. Every candidate must
    /// authenticate with exactly `service.public_key()` as its raw TLS key;
    /// CA authentication cannot substitute for it.
    pub service: ServiceName,
    /// Original URL port for HTTP authority construction.
    pub url_port: u16,
    /// Candidates sorted by ascending priority. Equal-priority order has no
    /// preference meaning; the host scheduler chooses attempt order.
    pub candidates: Vec<EndpointCandidate>,
    /// Expiry of the packet used to derive these candidates.
    /// The complete result may be reused until this time.
    pub expires_at: Instant,
}

/// Derive routes with direct raw-key TLS for the requested Pubky service.
/// The provider supplies the validated packet and owns caching, proof collection,
/// and I/O timeouts. The result expires with the packet's shortest record TTL.
///
/// # Errors
/// Rejects missing packets, expired records, ambiguous DNS sets, and unsupported
/// routing. No compatible ServiceMode record means failure, even if address
/// records exist.
/// Callers must check `expires_at` before reusing the result.
pub async fn derive_resolution(
    request: &ResolutionRequest,
    provider: &impl PacketProvider,
) -> Result<Resolution, Error> {
    let routing_owner = https_record_name(request)?;
    let packet = get_packet(provider, &routing_owner).await?;
    let records = records(&packet, routing_owner.as_str());
    let services = https_services(&records, request.supported_protocols())?;
    if services.is_empty() {
        return Err(Error::NoCompatibleEndpoint);
    }
    if packet.ttl(0, u32::MAX) == 0 {
        return Err(Error::Unsupported("zero TTL"));
    }
    let now = Instant::now();
    let remaining = Duration::from_secs(u64::from(packet.expires_in(0, u32::MAX)));
    let expires_at = now
        .checked_add(remaining)
        .ok_or(Error::InvalidTime("cache deadline overflow"))?;
    let mut candidates = Vec::with_capacity(services.len());
    for (service, protocols) in services {
        if service.target.iter().next().is_some()
            && !same_name(&service.target, routing_owner.as_str())
        {
            return Err(Error::Unsupported("alternate HTTPS target"));
        }
        let addresses = addresses(&records, service)?;
        let port = match service.get_param(3) {
            Some(SVCParam::Port(port)) => {
                NonZeroU16::new(*port).ok_or(Error::InvalidRecord("port zero"))?
            }
            _ => request.url_port,
        };
        candidates.push(EndpointCandidate {
            addresses,
            port,
            priority: service.priority,
            protocols,
        });
    }
    candidates.sort_by_key(|candidate| candidate.priority);
    // Evidence must still be fresh when the resolution is returned.
    if expires_at <= Instant::now() {
        return Err(Error::ExpiredRecord);
    }
    Ok(Resolution {
        service: request.service.clone(),
        url_port: request.url_port(),
        candidates,
        expires_at,
    })
}

fn https_record_name(request: &ResolutionRequest) -> Result<ServiceName, Error> {
    // HTTPS uses the service name on port 443 and a port-prefixed name otherwise.
    if request.url_port() == 443 {
        Ok(request.service.clone())
    } else {
        format!("_{}._https.{}", request.url_port(), request.service).parse()
    }
}

async fn get_packet(
    provider: &impl PacketProvider,
    name: &ServiceName,
) -> Result<Arc<SignedPacket>, Error> {
    let key = name.public_key();
    provider
        .get_packet(key)
        .await
        .map_err(|source| Error::Provider {
            key: Box::new(key.clone()),
            source: Box::new(source),
        })?
        .ok_or_else(|| Error::MissingPacket(Box::new(key.clone())))
}

fn https_services<'a>(
    records: &[&'a ResourceRecord<'a>],
    supported_protocols: &[HttpProtocol],
) -> Result<Vec<(&'a SVCB<'a>, Vec<HttpProtocol>)>, Error> {
    check_routing_cname(records)?;
    // AliasMode overrides ServiceMode before protocol filtering.
    check_https_aliases(records)?;
    let mut services = Vec::new();
    for record in records {
        let RData::HTTPS(https) = &record.rdata else {
            continue;
        };
        let protocols = compatible_protocols(&https.0, supported_protocols)?;
        if protocols.is_empty() {
            continue;
        }
        services.push((&https.0, protocols));
    }
    Ok(services)
}

fn check_https_aliases(records: &[&ResourceRecord<'_>]) -> Result<(), Error> {
    // RFC 9460 §2.4.1 permits mixed modes, but any AliasMode record makes
    // ServiceMode records ignored. Following aliases is not implemented.
    let mut aliases = records.iter().filter_map(|record| match &record.rdata {
        RData::HTTPS(https) if https.0.priority == 0 => Some(&https.0),
        _ => None,
    });
    let Some(alias) = aliases.next() else {
        return Ok(());
    };
    // Multiple aliases are permitted (§2.4.2); selecting one is unsupported.
    // A single root-target alias indicates that the service is unavailable.
    if aliases.next().is_none() && alias.target.iter().next().is_none() {
        return Err(Error::ServiceUnavailable);
    }
    Err(Error::Unsupported("HTTPS AliasMode"))
}

fn check_routing_cname(records: &[&ResourceRecord<'_>]) -> Result<(), Error> {
    if !records
        .iter()
        .any(|record| matches!(record.rdata, RData::CNAME(_)))
    {
        return Ok(());
    }
    if records.len() != 1 {
        return Err(Error::InvalidRecord("CNAME with other routing records"));
    }
    Err(Error::Unsupported("routing CNAME"))
}

fn records<'a>(packet: &'a SignedPacket, name: &str) -> Vec<&'a ResourceRecord<'a>> {
    // Match exact names; SDK relative-name and wildcard lookup conveniences
    // must not cross the requested service's authorization boundary.
    packet
        .all_resource_records()
        .filter(|record| same_name(&record.name, name))
        .collect()
}

fn same_name(name: &Name<'_>, expected: &str) -> bool {
    let labels = name.iter();
    let expected = expected.split('.');
    labels.len() == expected.clone().count()
        && labels
            .zip(expected)
            .all(|(label, expected)| label.as_ref().eq_ignore_ascii_case(expected.as_bytes()))
}

fn compatible_protocols(
    service: &SVCB<'_>,
    supported_protocols: &[HttpProtocol],
) -> Result<Vec<HttpProtocol>, Error> {
    let no_default = service.get_param(2).is_some();
    let alpn = match service.get_param(1) {
        Some(SVCParam::Alpn(alpn)) => Some(alpn),
        _ => None,
    };
    if no_default && alpn.is_none() {
        return Err(Error::InvalidRecord("no-default-alpn requires alpn"));
    }
    if let Some(SVCParam::Mandatory(keys)) = service.get_param(0) {
        if keys.iter().any(|key| service.get_param(*key).is_none()) {
            return Err(Error::InvalidRecord("mandatory parameter is absent"));
        }
        // ECH and unknown keys cannot be declared supported merely because
        // their bytes can be parsed. Optional unsupported parameters are ignored.
        if keys.iter().any(|key| !matches!(key, 1..=4 | 6)) {
            return Ok(Vec::new());
        }
    }
    Ok(supported_protocols
        .iter()
        .copied()
        .filter(|protocol| {
            let alpn_id = protocol
                .alpn()
                .try_into()
                .expect("static ALPN fits a DNS character string");
            (!no_default && *protocol == HttpProtocol::Http11)
                || alpn.is_some_and(|ids| ids.contains(&alpn_id))
        })
        .collect())
}

fn addresses(records: &[&ResourceRecord<'_>], service: &SVCB<'_>) -> Result<Vec<IpAddr>, Error> {
    let mut result: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.rdata {
            RData::A(address) => Some(IpAddr::V4(address.address.into())),
            RData::AAAA(address) => Some(IpAddr::V6(address.address.into())),
            _ => None,
        })
        .collect();
    // Hints are signed by the same routing authority and do not affect TLS.
    // Scheduling address records versus hints remains the host's responsibility.
    for param in service.iter_params() {
        match param {
            SVCParam::Ipv4Hint(ips) => result.extend(ips.iter().map(|ip| IpAddr::V4((*ip).into()))),
            SVCParam::Ipv6Hint(ips) => result.extend(ips.iter().map(|ip| IpAddr::V6((*ip).into()))),
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    result.retain(|address| seen.insert(*address));
    if result.is_empty() {
        return Err(Error::NoAddresses);
    }
    Ok(result)
}
