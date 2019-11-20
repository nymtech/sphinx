use crate::constants::NODE_ADDRESS_LENGTH;
use crate::header::filler::Filler;
use crate::header::header::{random_final_hop, MixNode, RouteElement};
use crate::header::keys::PayloadKey;
use crate::header::routing::{
    EncapsulatedRoutingInformation, EncryptedRoutingInformation, HeaderIntegrityMac,
};
use crate::utils::crypto;
use crate::Hop;
use curve25519_dalek::scalar::Scalar;

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
pub fn create(initial_secret: Scalar, route: &[RouteElement]) -> (SphinxHeader, Vec<PayloadKey>) {
    let key_material = keys::KeyMaterial::derive(route, initial_secret);
    let delays = delays::generate(route.len() - 1); // we don't generate delay for the destination
    let filler_string = Filler::new(&key_material.routing_keys[..route.len() - 1]);
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
) -> Result<(EncapsulatedRoutingInformation, [u8; NODE_ADDRESS_LENGTH]), SphinxUnwrapError> {
    if !header.routing_info.integrity_mac.verify(
        routing_keys.header_integrity_hmac_key,
        header.routing_info.enc_routing_information.get_value_ref(),
    ) {
        return Err(SphinxUnwrapError::IntegrityMacError);
    }

    let (next_hop_addr, next_hop_integrity_mac, next_hop_encrypted_routing_information) =
        unwrap::unwrap_routing_information(
            header.routing_info.enc_routing_information,
            routing_keys.stream_cipher_key,
        );
    Ok((
        EncapsulatedRoutingInformation {
            enc_routing_information: EncryptedRoutingInformation {
                value: next_hop_encrypted_routing_information,
            },
            integrity_mac: HeaderIntegrityMac {
                value: next_hop_integrity_mac,
            },
        },
        next_hop_addr,
    ))
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use super::*;

    #[test]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_4() {
        let mixnode1 = RouteElement::ForwardHop(MixNode {
            address: [5u8; NODE_ADDRESS_LENGTH],
            pub_key: crypto::generate_random_curve_point(),
        });
        let mixnode2 = RouteElement::ForwardHop(MixNode {
            address: [4u8; NODE_ADDRESS_LENGTH],
            pub_key: crypto::generate_random_curve_point(),
        });
        let mixnode3 = RouteElement::ForwardHop(MixNode {
            address: [2u8; NODE_ADDRESS_LENGTH],
            pub_key: crypto::generate_random_curve_point(),
        });
        let finaldest = random_final_hop();
        let route = [mixnode1, mixnode2, mixnode3, finaldest];

        let initial_secret = crypto::generate_secret();
        let (sphinx_header, payload_keys) = create(initial_secret, &route);

        let key_material = keys::KeyMaterial::derive(&route, initial_secret);

        let unwrapped_header = match process_header(sphinx_header, &key_material.routing_keys[0]) {
            Err(error) => panic!("Something went wrong in header unwrapping {:?}", error),
            Ok(unwrapped_header) => unwrapped_header,
        };
        // let (next_hop_encapsulated_routing_info, next_hop_addr) = unwrapped_header;
        // assert_eq!([4u8; NODE_ADDRESS_LENGTH], next_hop_addr);
    }
}
