use crate::constants::INTEGRITY_MAC_SIZE;
use crate::header::header::RouteElement;
use crate::header::keys::PayloadKey;
use crate::utils::crypto;
use crate::Hop;

pub mod delays;
pub mod filler;
pub mod header;
pub mod keys;
pub mod routing;
pub mod unwrap;

pub struct SphinxHeader {
    pub shared_secret: crypto::SharedSecret,
    pub routing_info: routing::RoutingInfo,
}

#[derive(Debug)]
pub enum SphinxUnwrapError {
    IntegrityMacError,
}

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create(route: &[RouteElement]) -> (SphinxHeader, Vec<PayloadKey>) {
    let initial_secret = crypto::generate_secret();
    let key_material = keys::derive(route, initial_secret);
    let delays = delays::generate(route.len() - 1); // we don't generate delay for the destination
    let filler_string = filler::generate_pseudorandom_filler(&key_material.routing_keys);
    let routing_info =
        routing::generate_all_routing_info(route, &key_material.routing_keys, filler_string);

    // encapsulate routing information, compute MACs
    (
        SphinxHeader {
            shared_secret: key_material.initial_shared_secret,
            routing_info,
        },
        key_material
            .routing_keys
            .iter()
            .map(|routing_key| routing_key.payload_key)
            .collect(),
    )
}

pub fn process_header(
    header: SphinxHeader,
    routing_keys: &routing::RoutingKeys,
) -> Result<(SphinxHeader, Hop), SphinxUnwrapError> {
    if !unwrap::check_integrity_mac(
        header.routing_info.header_integrity_hmac,
        routing_keys.header_integrity_hmac_key,
        header.routing_info.enc_header,
    ) {
        return Err(SphinxUnwrapError::IntegrityMacError);
    };

    let tmp = unwrap::unwrap_routing_information(header, &routing_keys.stream_cipher_key);
    Ok((
        SphinxHeader {
            shared_secret: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            routing_info: routing::RoutingInfo {
                enc_header: [0u8; routing::ROUTING_INFO_SIZE],
                header_integrity_hmac: [0u8; INTEGRITY_MAC_SIZE],
            },
        },
        Hop {
            host: header::RouteElement::ForwardHop(header::MixNode {
                address: header::node_address_fixture(),
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            }),
            delay: 0.0,
        },
    ))
}
