// Copyright 2020 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::constants::HEADER_INTEGRITY_MAC_SIZE;
use crate::crypto;
use crate::crypto::PublicKey;
use crate::header::delays::Delay;
use crate::header::filler::Filler;
use crate::header::keys::{BlindingFactor, PayloadKey, StreamCipherKey};
use crate::header::routing::nodes::{EncryptedRoutingInformation, ParsedRawRoutingInformation};
use crate::header::routing::{EncapsulatedRoutingInformation, ENCRYPTED_ROUTING_INFO_SIZE};
use crate::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier};
use crate::{Error, ErrorKind, Result};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

pub mod delays;
pub mod filler;
pub mod keys;
pub mod mac;
pub mod routing;

// 32 represents size of a MontgomeryPoint on Curve25519
pub const HEADER_SIZE: usize = 32 + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE;

#[derive(Clone)]
pub struct SphinxHeader {
    pub shared_secret: crypto::SharedSecret,
    pub routing_info: EncapsulatedRoutingInformation,
}

pub enum ProcessedHeader {
    ProcessedHeaderForwardHop(SphinxHeader, NodeAddressBytes, Delay, PayloadKey),
    ProcessedHeaderFinalHop(DestinationAddressBytes, SURBIdentifier, PayloadKey),
}

impl SphinxHeader {
    // needs client's secret key, how should we inject this?
    // needs to deal with SURBs too at some point
    pub fn new(
        initial_secret: Scalar,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
    ) -> (Self, Vec<PayloadKey>) {
        let key_material = keys::KeyMaterial::derive(route, initial_secret);
        let filler_string = Filler::new(&key_material.routing_keys[..route.len() - 1]);
        let routing_info = routing::EncapsulatedRoutingInformation::new(
            route,
            destination,
            &delays,
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

    fn unwrap_routing_information(
        enc_routing_information: EncryptedRoutingInformation,
        stream_cipher_key: StreamCipherKey,
    ) -> Result<ParsedRawRoutingInformation> {
        // we have to add padding to the encrypted routing information before decrypting, otherwise we gonna lose information
        enc_routing_information
            .add_zero_padding()
            .decrypt(stream_cipher_key)
            .parse()
    }

    pub fn process(self, node_secret_key: Scalar) -> Result<ProcessedHeader> {
        let shared_secret = self.shared_secret;
        let shared_key = keys::KeyMaterial::compute_shared_key(shared_secret, &node_secret_key);
        let routing_keys = keys::RoutingKeys::derive(shared_key);

        if !self.routing_info.integrity_mac.verify(
            routing_keys.header_integrity_hmac_key,
            self.routing_info.enc_routing_information.get_value_ref(),
        ) {
            return Err(Error::new(
                ErrorKind::InvalidHeader,
                "failed to verify integrity MAC",
            ));
        }

        // blind the shared_secret in the header
        let new_shared_secret =
            self.blind_the_shared_secret(shared_secret, routing_keys.blinding_factor);

        let unwrapped_routing_information = Self::unwrap_routing_information(
            self.routing_info.enc_routing_information,
            routing_keys.stream_cipher_key,
        )
        .unwrap();
        match unwrapped_routing_information {
            ParsedRawRoutingInformation::ForwardHopRoutingInformation(
                next_hop_address,
                delay,
                new_encapsulated_routing_info,
            ) => Ok(ProcessedHeader::ProcessedHeaderForwardHop(
                SphinxHeader {
                    shared_secret: new_shared_secret,
                    routing_info: new_encapsulated_routing_info,
                },
                next_hop_address,
                delay,
                routing_keys.payload_key,
            )),
            ParsedRawRoutingInformation::FinalHopRoutingInformation(
                destination_address,
                identifier,
            ) => Ok(ProcessedHeader::ProcessedHeaderFinalHop(
                destination_address,
                identifier,
                routing_keys.payload_key,
            )),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.shared_secret
            .as_bytes()
            .iter()
            .cloned()
            .chain(self.routing_info.to_bytes())
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidHeader,
                format!(
                    "tried to recover using {} bytes, expected {}",
                    bytes.len(),
                    HEADER_SIZE
                ),
            ));
        }

        let mut shared_secret_bytes = [0u8; 32];
        // first 32 bytes represent the shared secret
        shared_secret_bytes.copy_from_slice(&bytes[..32]);

        // the rest are for the encapsulated routing info
        let encapsulated_routing_info_bytes = bytes[32..HEADER_SIZE].to_vec();

        let routing_info =
            EncapsulatedRoutingInformation::from_bytes(&encapsulated_routing_info_bytes)?;

        Ok(SphinxHeader {
            shared_secret: MontgomeryPoint(shared_secret_bytes),
            routing_info,
        })
    }

    fn blind_the_shared_secret(
        &self,
        shared_secret: PublicKey,
        blinding_factor: BlindingFactor,
    ) -> PublicKey {
        let blinding_factor = Scalar::from_bytes_mod_order(blinding_factor);
        shared_secret * blinding_factor
    }
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::route::destination_fixture;
    use std::time::Duration;

    use super::*;

    #[test]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let destination = destination_fixture();
        let initial_secret = crypto::generate_secret();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let (sphinx_header, _) = SphinxHeader::new(initial_secret, &route, &delays, &destination);

        //let (new_header, next_hop_address, _) = sphinx_header.process(node1_sk).unwrap();
        let new_header = match sphinx_header.process(node1_sk).unwrap() {
            ProcessedHeader::ProcessedHeaderForwardHop(new_header, next_hop_address, delay, _) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                new_header
            }
            _ => panic!(),
        };

        let new_header2 = match new_header.process(node2_sk).unwrap() {
            ProcessedHeader::ProcessedHeaderForwardHop(new_header, next_hop_address, delay, _) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                new_header
            }
            _ => panic!(),
        };
        match new_header2.process(node3_sk).unwrap() {
            ProcessedHeader::ProcessedHeaderFinalHop(final_destination, _, _) => {
                assert_eq!(destination.address, final_destination);
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod unwrap_routing_information {
    use crate::constants::{
        HEADER_INTEGRITY_MAC_SIZE, NODE_ADDRESS_LENGTH, NODE_META_INFO_SIZE,
        STREAM_CIPHER_OUTPUT_LENGTH,
    };
    use crate::crypto;
    use crate::header::routing::{ENCRYPTED_ROUTING_INFO_SIZE, FORWARD_HOP};
    use crate::utils;

    use super::*;

    #[test]
    fn it_returns_correct_unwrapped_routing_information() {
        let mut routing_info = [9u8; ENCRYPTED_ROUTING_INFO_SIZE];
        routing_info[0] = FORWARD_HOP;
        let stream_cipher_key = [1u8; crypto::STREAM_CIPHER_KEY_SIZE];
        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &stream_cipher_key,
            &crypto::STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let encrypted_routing_info_vec = utils::bytes::xor(
            &routing_info,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );
        let mut encrypted_routing_info_array = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        encrypted_routing_info_array.copy_from_slice(&encrypted_routing_info_vec);

        let enc_routing_info =
            EncryptedRoutingInformation::from_bytes(encrypted_routing_info_array);

        log::trace!("{:?}", routing_info.len());
        log::trace!("{:?}", pseudorandom_bytes.len());
        let expected_next_hop_encrypted_routing_information = [
            routing_info[NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE..].to_vec(),
            pseudorandom_bytes
                [NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE..]
                .to_vec(),
        ]
        .concat();
        let next_hop_encapsulated_routing_info =
            match SphinxHeader::unwrap_routing_information(enc_routing_info, stream_cipher_key)
                .unwrap()
            {
                ParsedRawRoutingInformation::ForwardHopRoutingInformation(
                    next_hop_address,
                    _delay,
                    next_hop_encapsulated_routing_info,
                ) => {
                    assert_eq!(
                        routing_info[1..1 + NODE_ADDRESS_LENGTH],
                        next_hop_address.to_bytes()
                    );
                    assert_eq!(
                        routing_info
                            [NODE_ADDRESS_LENGTH..NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE],
                        next_hop_encapsulated_routing_info
                            .integrity_mac
                            .clone()
                            .get_value()
                    );
                    next_hop_encapsulated_routing_info
                }
                _ => panic!(),
            };

        let next_hop_encrypted_routing_information = next_hop_encapsulated_routing_info
            .enc_routing_information
            .get_value_ref();

        for i in 0..expected_next_hop_encrypted_routing_information.len() {
            assert_eq!(
                expected_next_hop_encrypted_routing_information[i],
                next_hop_encrypted_routing_information[i]
            );
        }
    }
}

#[cfg(test)]
mod converting_header_to_bytes {
    use crate::crypto::generate_random_curve_point;
    use crate::header::routing::encapsulated_routing_information_fixture;

    use super::*;

    #[test]
    fn it_is_possible_to_convert_back_and_forth() {
        let encapsulated_routing_info = encapsulated_routing_information_fixture();
        let header = SphinxHeader {
            shared_secret: generate_random_curve_point(),
            routing_info: encapsulated_routing_info,
        };

        let header_bytes = header.to_bytes();
        let recovered_header = SphinxHeader::from_bytes(&header_bytes).unwrap();

        assert_eq!(header.shared_secret, recovered_header.shared_secret);
        assert_eq!(
            header.routing_info.to_bytes(),
            recovered_header.routing_info.to_bytes()
        );
    }
}
