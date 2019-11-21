use crate::constants::NODE_ADDRESS_LENGTH;
use crate::header::filler::Filler;
use crate::header::keys::PayloadKey;
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::nodes::EncryptedRoutingInformation;
use crate::header::routing::EncapsulatedRoutingInformation;
use crate::route::{Destination, Node};
use crate::utils::crypto;
use crate::utils::crypto::{compute_keyed_hmac, PublicKey, SharedKey};
use crate::Hop;
use curve25519_dalek::scalar::Scalar;

pub mod delays;
pub mod filler;
pub mod keys;
pub mod mac;
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
pub fn create(
    initial_secret: Scalar,
    route: &[Node],
    destination: &Destination,
) -> (SphinxHeader, Vec<PayloadKey>) {
    let key_material = keys::KeyMaterial::derive(route, initial_secret);
    let delays = delays::generate(route.len() - 1); // we don't generate delay for the destination
    let filler_string = Filler::new(&key_material.routing_keys[..route.len() - 1]);
    let routing_info = routing::EncapsulatedRoutingInformation::new(
        route,
        destination,
        &key_material.routing_keys,
        filler_string,
    );

    // encapsulate header.routing information, compute MACs
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
    node_secret_key: Scalar,
) -> Result<(SphinxHeader, [u8; NODE_ADDRESS_LENGTH], PayloadKey), SphinxUnwrapError> {
    let shared_secret = header.shared_secret;
    let shared_key = keys::KeyMaterial::compute_shared_key(shared_secret, &node_secret_key);
    let routing_keys = keys::RoutingKeys::derive(shared_key);
    println!("Routing key while processing {:?}", routing_keys);

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

    // blind the shared_secret in the header
    let new_shared_secret = blind_the_shared_secret(shared_secret, shared_key);

    let next_hop_encapsulated_routing_info = EncapsulatedRoutingInformation::encapsulate(
        EncryptedRoutingInformation::from_bytes(next_hop_encrypted_routing_information),
        HeaderIntegrityMac::from_bytes(next_hop_integrity_mac),
    );
    let new_header = SphinxHeader {
        shared_secret: new_shared_secret,
        routing_info: next_hop_encapsulated_routing_info,
    };

    Ok((new_header, next_hop_addr, routing_keys.payload_key))
}

fn blind_the_shared_secret(shared_secret: PublicKey, shared_key: SharedKey) -> PublicKey {
    let hmac_full = compute_keyed_hmac(
        shared_secret.to_bytes().to_vec(),
        &shared_key.to_bytes().to_vec(),
    );
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&hmac_full[..32]);
    let blidning_factor = Scalar::from_bytes_mod_order(hmac);
    shared_secret * blidning_factor
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use super::*;
    use crate::route::destination_fixture;

    #[test]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_4() {
        let (node1_sk, node1_pk) = crypto::key_pair_fixture();
        let node1 = Node {
            address: [5u8; NODE_ADDRESS_LENGTH],
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = crypto::key_pair_fixture();
        let node2 = Node {
            address: [4u8; NODE_ADDRESS_LENGTH],
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::key_pair_fixture();
        let node3 = Node {
            address: [2u8; NODE_ADDRESS_LENGTH],
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let destination = destination_fixture();
        let initial_secret = crypto::generate_secret();
        let (sphinx_header, payload_keys) = create(initial_secret, &route, &destination);

        //        let unwrapped_header = match process_header(sphinx_header, node1_sk) {
        //            Err(error) => panic!("Something went wrong in header unwrapping {:?}", error),
        //            Ok(unwrapped_header) => unwrapped_header,
        //        };
        // let (next_hop_encapsulated_routing_info, next_hop_addr) = unwrapped_header;
        // assert_eq!([4u8; NODE_ADDRESS_LENGTH], next_hop_addr);
    }
}
