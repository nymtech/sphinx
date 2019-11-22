use curve25519_dalek::scalar::Scalar;

use crate::crypto;
use crate::crypto::{compute_keyed_hmac, PublicKey, SharedKey};
use crate::header::filler::Filler;
use crate::header::keys::PayloadKey;
use crate::header::routing::EncapsulatedRoutingInformation;
use crate::route::{Destination, Node, NodeAddressBytes};

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

impl SphinxHeader {
    // needs client's secret key, how should we inject this?
    // needs to deal with SURBs too at some point
    pub fn new(
        initial_secret: Scalar,
        route: &[Node],
        destination: &Destination,
    ) -> (SphinxHeader, Vec<PayloadKey>) {
        let key_material = keys::KeyMaterial::derive(route, initial_secret);
        let _ = delays::generate(route.len());
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

    pub fn process(
        self,
        node_secret_key: Scalar,
    ) -> Result<(SphinxHeader, NodeAddressBytes, PayloadKey), SphinxUnwrapError> {
        let shared_secret = self.shared_secret;
        let shared_key = keys::KeyMaterial::compute_shared_key(shared_secret, &node_secret_key);
        let routing_keys = keys::RoutingKeys::derive(shared_key);

        if !self.routing_info.integrity_mac.verify(
            routing_keys.header_integrity_hmac_key,
            self.routing_info.enc_routing_information.get_value_ref(),
        ) {
            return Err(SphinxUnwrapError::IntegrityMacError);
        }

        // blind the shared_secret in the header
        let new_shared_secret = self.blind_the_shared_secret(shared_secret, shared_key);

        let (next_hop_address, encapsulated_next_hop) = unwrap::unwrap_routing_information(
            self.routing_info.enc_routing_information,
            routing_keys.stream_cipher_key,
        );

        let new_header = SphinxHeader {
            shared_secret: new_shared_secret,
            routing_info: encapsulated_next_hop,
        };

        Ok((new_header, next_hop_address, routing_keys.payload_key))
    }

    fn blind_the_shared_secret(
        &self,
        shared_secret: PublicKey,
        shared_key: SharedKey,
    ) -> PublicKey {
        let hmac_full = compute_keyed_hmac(
            shared_secret.to_bytes().to_vec(),
            &shared_key.to_bytes().to_vec(),
        );
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&hmac_full[..32]);
        let blinding_factor = Scalar::from_bytes_mod_order(hmac);
        shared_secret * blinding_factor
    }
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::route::destination_fixture;

    use super::*;

    #[test]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node {
            address: [5u8; NODE_ADDRESS_LENGTH],
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: [4u8; NODE_ADDRESS_LENGTH],
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node {
            address: [2u8; NODE_ADDRESS_LENGTH],
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let destination = destination_fixture();
        let initial_secret = crypto::generate_secret();
        let (sphinx_header, _) = SphinxHeader::new(initial_secret, &route, &destination);

        let (new_header, next_hop_address, _) = sphinx_header.process(node1_sk).unwrap();
        assert_eq!([4u8; NODE_ADDRESS_LENGTH], next_hop_address);

        let (new_header2, next_hop_address2, _) = new_header.process(node2_sk).unwrap();
        assert_eq!([2u8; NODE_ADDRESS_LENGTH], next_hop_address2);

        let (_, next_hop_address3, _) = new_header2.process(node3_sk).unwrap();
        assert_eq!(destination.address, next_hop_address3);
    }
}
