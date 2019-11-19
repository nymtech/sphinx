use crate::header::filler::Filler;
use crate::header::header::RouteElement;
use crate::header::keys::PayloadKey;
use crate::header::routing::EncapsulatedRoutingInformation;
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
    pub routing_info: EncapsulatedRoutingInformation,
}

#[derive(Debug)]
pub enum SphinxUnwrapError {
    IntegrityMacError,
}

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create(route: &[RouteElement]) -> (SphinxHeader, Vec<PayloadKey>) {
    let initial_secret = crypto::generate_secret();
    let key_material = keys::KeyMaterial::derive(route, initial_secret);
    let delays = delays::generate(route.len() - 1); // we don't generate delay for the destination
    let filler_string = Filler::new(&key_material.routing_keys);
    let routing_info = routing::EncapsulatedRoutingInformation::new(
        route,
        &key_material.routing_keys,
        filler_string,
    )
    .unwrap();

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
    routing_keys: &keys::RoutingKeys,
) -> Result<(SphinxHeader, Hop), SphinxUnwrapError> {
    if !header.routing_info.integrity_mac.verify(
        routing_keys.header_integrity_hmac_key,
        header.routing_info.enc_routing_information.get_value_ref(),
    ) {
        return Err(SphinxUnwrapError::IntegrityMacError);
    }

    let tmp = unwrap::unwrap_routing_information(header, routing_keys.stream_cipher_key);
    Ok((
        SphinxHeader {
            shared_secret: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            routing_info: routing::encapsulated_routing_information_fixture(),
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
