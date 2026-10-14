//! Signed packet fixtures covering routing, direct TLS, and freshness.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use pkarr::{
    Keypair, SignedPacket, SignedPacketBuilder,
    dns::{
        Name,
        rdata::{SVCB, SVCParam},
    },
};
use pkresolve::{
    Error, HttpProtocol, PublicKey, Resolution, ResolutionRequest, ServiceName,
    derive_resolution as derive_from_provider,
};

const TTL: u32 = 300;

fn now() -> SystemTime {
    SystemTime::now()
}
fn key(seed: u8) -> Keypair {
    Keypair::from_secret_key(&[seed; 32])
}
fn name(input: &str) -> Name<'_> {
    input.try_into().unwrap()
}
fn service(key: &Keypair) -> ServiceName {
    key.to_z32().parse().unwrap()
}
fn request(key: &Keypair) -> ResolutionRequest {
    ResolutionRequest::new(
        service(key),
        443,
        vec![HttpProtocol::Http2, HttpProtocol::Http11],
    )
    .unwrap()
}
fn proof(
    builder: SignedPacketBuilder,
    key: &Keypair,
    signed_age: u64,
    observed_age: u64,
) -> SignedPacket {
    let mut packet = builder
        .timestamp((now() - Duration::from_secs(signed_age)).into())
        .sign(key)
        .unwrap();
    packet.set_last_seen(&(now() - Duration::from_secs(observed_age)).into());
    packet
}
fn route(priority: u16, port: u16) -> SVCB<'static> {
    let mut svc = SVCB::new(priority, name("."));
    svc.set_port(port);
    svc.set_alpn(&["h2".try_into().unwrap()]);
    svc
}
fn direct_builder() -> SignedPacketBuilder {
    SignedPacket::builder()
        .https(name("."), route(1, 443), TTL)
        .address(name("."), "203.0.113.10".parse().unwrap(), TTL)
}
fn packet_cache(packets: &[SignedPacket]) -> HashMap<PublicKey, Arc<SignedPacket>> {
    packets
        .iter()
        .map(|packet| (packet.public_key(), Arc::new(packet.clone())))
        .collect()
}
fn derive_resolution(
    req: &ResolutionRequest,
    packets: &HashMap<PublicKey, Arc<SignedPacket>>,
) -> Result<Resolution, Error> {
    futures_lite::future::block_on(derive_from_provider(req, packets))
}

fn assert_remaining_ttl(resolution: &Resolution, expected_seconds: u64) {
    let remaining = resolution
        .expires_at
        .saturating_duration_since(Instant::now());
    let expected = Duration::from_secs(expected_seconds);
    assert!(remaining <= expected, "{remaining:?} > {expected:?}");
    assert!(
        remaining > expected - Duration::from_secs(1),
        "{remaining:?} too short for {expected:?}"
    );
}

fn resolve(req: &ResolutionRequest, proofs: &[SignedPacket]) -> Result<Resolution, Error> {
    let packets = packet_cache(proofs);
    derive_resolution(req, &packets)
}

fn tls_owner(port: u16, key: &Keypair) -> String {
    format!("_{port}._tcp.{}", key.to_z32())
}

#[test]
fn direct_route_uses_verified_key_and_preserves_original_service() {
    let alice = key(1);
    let req = request(&alice);
    let result = resolve(&req, &[proof(direct_builder(), &alice, 10, 0)]).unwrap();
    let candidate = &result.candidates[0];
    assert_eq!(
        candidate.addresses.as_slice(),
        &["203.0.113.10".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(candidate.port.get(), 443);
    assert_eq!(result.service.public_key(), &alice.public_key());
    assert_eq!(&result.service, req.service());
    assert_eq!(result.url_port, 443);
    assert_eq!(
        candidate.protocols.as_slice(),
        &[HttpProtocol::Http2, HttpProtocol::Http11]
    );
}

#[test]
fn all_endpoint_ports_use_destination_key_and_ignore_tls_delegation() {
    let alice = key(1);
    let provider = key(2);
    let target = tls_owner(8443, &provider);
    let alice_packet = proof(
        direct_builder()
            .https(name("."), route(2, 8443), TTL)
            .cname(name("_8443._tcp"), name(&target), 120),
        &alice,
        10,
        20,
    );
    let provider_packet = proof(SignedPacket::builder(), &provider, 30, 40);
    for proofs in [
        vec![alice_packet.clone()],
        vec![alice_packet.clone(), provider_packet.clone()],
        vec![provider_packet, alice_packet],
    ] {
        let packets = packet_cache(&proofs);
        let result = derive_resolution(&request(&alice), &packets).unwrap();
        let candidates = &result.candidates;
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].port.get(), 443);
        assert_eq!(result.service.public_key(), &alice.public_key());
        assert_eq!(candidates[1].port.get(), 8443);
        assert_eq!(&result.service, &service(&alice));
        // Ignored TLS delegation records do not shorten routing lifetimes.
        assert_remaining_ttl(&result, 280);
    }
}

#[test]
fn scoped_services_also_use_the_destination_key() {
    let alice = key(1);
    let provider = key(2);
    let target = tls_owner(443, &provider);
    let packet = proof(
        direct_builder()
            .https(name("_pubky"), route(1, 443), TTL)
            .address(name("_pubky"), "203.0.113.11".parse().unwrap(), TTL)
            .cname(name("_443._tcp._pubky"), name(&target), TTL),
        &alice,
        0,
        0,
    );
    let req = ResolutionRequest::new(
        format!("_pubky.{}", alice.to_z32()).parse().unwrap(),
        443,
        vec![HttpProtocol::Http11],
    )
    .unwrap();
    let scoped = resolve(&req, std::slice::from_ref(&packet)).unwrap();
    assert_eq!(scoped.service.public_key(), &alice.public_key());
    assert_eq!(&scoped.service, req.service());
    let result = resolve(&request(&alice), &[packet]).unwrap();
    assert_eq!(result.service.public_key(), &alice.public_key());
}

#[test]
fn nondefault_url_and_connection_ports_preserve_destination_tls_key() {
    let alice = key(1);
    let provider = key(2);
    let target = tls_owner(9443, &provider);
    let packet = proof(
        SignedPacket::builder()
            .https(name("_8443._https"), route(1, 9443), TTL)
            .address(name("_8443._https"), "203.0.113.10".parse().unwrap(), TTL)
            .cname(name("_9443._tcp"), name(&target), TTL),
        &alice,
        0,
        0,
    );
    let provider_packet = proof(SignedPacket::builder(), &provider, 0, 0);
    let req = ResolutionRequest::new(service(&alice), 8443, vec![HttpProtocol::Http2]).unwrap();
    let result = resolve(&req, &[packet, provider_packet]).unwrap();
    assert_eq!(result.url_port, 8443);
    assert_eq!(result.candidates[0].port.get(), 9443);
    assert_eq!(result.service.public_key(), &alice.public_key());
    assert_eq!(&result.service, &service(&alice));
}

#[test]
fn record_ttl_controls_reuse_independently_of_publication_age() {
    let alice = key(1);
    let packet = proof(direct_builder(), &alice, 900_000, 5);
    let verified = packet_cache(&[packet]);
    let result = derive_resolution(&request(&alice), &verified).unwrap();
    assert_remaining_ttl(&result, 295);
    let packet = proof(direct_builder(), &alice, 10, 40);
    let verified = packet_cache(&[packet]);
    let result = derive_resolution(&request(&alice), &verified).unwrap();
    assert_remaining_ttl(&result, 260);
}

#[test]
fn address_ttl_can_expire_before_service_record() {
    let alice = key(1);
    let packet = proof(
        SignedPacket::builder()
            .https(name("."), route(1, 443), TTL)
            .address(name("."), "203.0.113.10".parse().unwrap(), 30),
        &alice,
        0,
        30,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::ExpiredRecord)
    ));
}

#[test]
fn zero_ttl_is_explicitly_deferred() {
    let alice = key(1);
    let packet = proof(
        SignedPacket::builder()
            .https(name("."), route(1, 443), 0)
            .address(name("."), "203.0.113.10".parse().unwrap(), TTL),
        &alice,
        0,
        0,
    );
    let verified = packet_cache(&[packet]);
    assert!(matches!(
        derive_resolution(&request(&alice), &verified),
        Err(Error::Unsupported("zero TTL"))
    ));
}

#[test]
fn long_record_ttls_are_not_capped_by_packet_or_cache_age() {
    let alice = key(1);
    let packet = proof(
        SignedPacket::builder()
            .https(name("."), route(1, 443), 3600)
            .address(name("."), "203.0.113.10".parse().unwrap(), 3600),
        &alice,
        900_000,
        1200,
    );
    let packets = packet_cache(&[packet]);
    let result = derive_resolution(&request(&alice), &packets).unwrap();
    assert_remaining_ttl(&result, 2400);

    let expired = proof(direct_builder(), &alice, 900_000, 600);
    assert!(matches!(
        resolve(&request(&alice), &[expired]),
        Err(Error::ExpiredRecord)
    ));
}

#[test]
fn future_observation_times_do_not_need_a_clock_skew_policy() {
    let alice = key(1);
    for seconds in [5, 6] {
        let mut packet = proof(direct_builder(), &alice, 0, 0);
        packet.set_last_seen(&(now() + Duration::from_secs(seconds)).into());
        assert!(resolve(&request(&alice), &[packet]).is_ok());
        let signed = direct_builder()
            .timestamp((now() + Duration::from_secs(seconds)).into())
            .sign(&alice)
            .unwrap();
        let mut packet = signed;
        packet.set_last_seen(&now().into());
        assert!(resolve(&request(&alice), &[packet]).is_ok());
    }
}

#[test]
fn bare_addresses_and_http3_only_records_do_not_enable_fallback() {
    let alice = key(1);
    let addresses =
        SignedPacket::builder().address(name("."), "203.0.113.10".parse().unwrap(), TTL);
    assert!(matches!(
        resolve(&request(&alice), &[proof(addresses.clone(), &alice, 0, 0)]),
        Err(Error::NoCompatibleEndpoint)
    ));
    let mut svc = route(1, 443);
    svc.set_alpn(&["h3".try_into().unwrap()]);
    svc.set_no_default_alpn();
    assert!(matches!(
        resolve(
            &request(&alice),
            &[proof(addresses.https(name("."), svc, TTL), &alice, 0, 0)]
        ),
        Err(Error::NoCompatibleEndpoint)
    ));
}

#[test]
fn alpn_defaults_and_client_preferences_are_applied() {
    let alice = key(1);
    let mut svc = route(1, 443);
    svc.set_no_default_alpn();
    let packet = proof(
        SignedPacket::builder().https(name("."), svc, TTL).address(
            name("."),
            "203.0.113.10".parse().unwrap(),
            TTL,
        ),
        &alice,
        0,
        0,
    );
    let result = resolve(&request(&alice), std::slice::from_ref(&packet)).unwrap();
    assert_eq!(
        result.candidates[0].protocols.as_slice(),
        &[HttpProtocol::Http2]
    );
    let req = ResolutionRequest::new(service(&alice), 443, vec![HttpProtocol::Http11]).unwrap();
    assert!(matches!(
        resolve(&req, &[packet]),
        Err(Error::NoCompatibleEndpoint)
    ));
    let svc = SVCB::new(1, name("."));
    let packet = proof(
        SignedPacket::builder().https(name("."), svc, TTL).address(
            name("."),
            "203.0.113.10".parse().unwrap(),
            TTL,
        ),
        &alice,
        0,
        0,
    );
    assert_eq!(
        resolve(&request(&alice), &[packet]).unwrap().candidates[0]
            .protocols
            .as_slice(),
        &[HttpProtocol::Http11]
    );
}

#[test]
fn unknown_mandatory_parameters_skip_candidate_but_missing_values_fail() {
    let alice = key(1);
    let mut svc = route(1, 443);
    svc.set_mandatory([100].into_iter());
    let packet = proof(
        SignedPacket::builder().https(name("."), svc.clone(), TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::InvalidRecord(_))
    ));
    svc.set_param(SVCParam::Unknown(100, b"extension"[..].into()));
    let packet = proof(
        SignedPacket::builder().https(name("."), svc, TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::NoCompatibleEndpoint)
    ));
}

#[test]
fn no_default_alpn_without_alpn_is_invalid() {
    let alice = key(1);
    let svc = SVCB::new(1, name(".")).with_param(SVCParam::NoDefaultAlpn);
    let packet = proof(
        SignedPacket::builder().https(name("."), svc, TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::InvalidRecord(_))
    ));
}

#[test]
fn unsupported_aliases_take_precedence_over_service_records() {
    let alice = key(1);
    let unavailable = proof(
        SignedPacket::builder().https(name("."), SVCB::new(0, name(".")), TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[unavailable]),
        Err(Error::ServiceUnavailable)
    ));
    let alias = SVCB::new(0, name("edge.example"));
    let packet = proof(
        SignedPacket::builder().https(name("."), alias.clone(), TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::Unsupported("HTTPS AliasMode"))
    ));
    let packet = proof(
        direct_builder().https(name("."), alias.clone(), TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::Unsupported("HTTPS AliasMode"))
    ));
    let packet = proof(
        direct_builder().https(name("."), alias, TTL).https(
            name("."),
            SVCB::new(0, name("other.example")),
            TTL,
        ),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::Unsupported("HTTPS AliasMode"))
    ));
    // A root-target alias disables the service even alongside ServiceMode.
    let packet = proof(
        direct_builder().https(name("."), SVCB::new(0, name(".")), TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::ServiceUnavailable)
    ));
    let packet = proof(
        SignedPacket::builder().https(name("."), SVCB::new(1, name("edge.example")), TTL),
        &alice,
        0,
        0,
    );
    assert!(matches!(
        resolve(&request(&alice), &[packet]),
        Err(Error::Unsupported("alternate HTTPS target"))
    ));
}

#[test]
fn hints_supply_routes_without_granting_tls_authority() {
    let alice = key(1);
    let mut svc = route(1, 443);
    svc.set_ipv4hint(&[u32::from(
        "203.0.113.10".parse::<std::net::Ipv4Addr>().unwrap(),
    )]);
    let packet = proof(
        SignedPacket::builder().https(name("."), svc, TTL),
        &alice,
        0,
        0,
    );
    let result = resolve(&request(&alice), &[packet]).unwrap();
    assert_eq!(result.service.public_key(), &alice.public_key());
    assert_eq!(
        result.candidates[0].addresses.as_slice(),
        &["203.0.113.10".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn service_name_validation_preserves_scopes_and_rejects_urls_and_wildcards() {
    let alice = key(1);
    let upper = format!("APP.{}.", alice.to_z32().to_ascii_uppercase());
    let parsed: ServiceName = upper.parse().unwrap();
    assert_eq!(parsed.as_str(), format!("app.{}", alice.to_z32()));
    for prefix in ["https://", "*.", ".", "-app.", "app..", "é."] {
        assert!(
            format!("{prefix}{}", alice.to_z32())
                .parse::<ServiceName>()
                .is_err()
        );
    }
    assert!(ResolutionRequest::new(service(&alice), 0, vec![HttpProtocol::Http11]).is_err());
    assert!(ResolutionRequest::new(service(&alice), 443, vec![]).is_err());
}

#[test]
fn publication_timestamp_does_not_affect_record_ttl() {
    let alice = key(1);
    let signed = direct_builder()
        .timestamp(u64::MAX.into())
        .sign(&alice)
        .unwrap();
    let mut packet = signed;
    packet.set_last_seen(&now().into());
    assert!(resolve(&request(&alice), &[packet]).is_ok());
}

#[test]
fn address_deduplication_preserves_record_and_hint_order_across_ip_families() {
    let alice = key(1);
    let ipv4: std::net::Ipv4Addr = "203.0.113.10".parse().unwrap();
    let ipv6: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let hinted: std::net::Ipv4Addr = "203.0.113.11".parse().unwrap();
    let mut svc = route(1, 443);
    svc.set_ipv4hint(&[ipv4.into(), hinted.into(), hinted.into()]);
    svc.set_ipv6hint(&[ipv6.into()]);
    let packet = proof(
        SignedPacket::builder()
            .https(name("."), svc, TTL)
            .aaaa(name("."), ipv6, TTL)
            .a(name("."), ipv4, TTL)
            .a(name("."), ipv4, TTL),
        &alice,
        0,
        0,
    );
    let result = resolve(&request(&alice), &[packet]).unwrap();
    assert_eq!(
        result.candidates[0].addresses.as_slice(),
        &[IpAddr::V6(ipv6), IpAddr::V4(ipv4), IpAddr::V4(hinted)]
    );
}
