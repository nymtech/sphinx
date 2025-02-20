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
use crate::header::delays::Delay;
use crate::header::filler::Filler;
use crate::header::keys::{KeyMaterial, PayloadKey};
use crate::header::routing::nodes::ParsedRawRoutingInformationData;
use crate::header::routing::{EncapsulatedRoutingInformation, ENCRYPTED_ROUTING_INFO_SIZE};
use crate::packet::ProcessedPacketData;
use crate::payload::Payload;
use crate::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier};
use crate::version::{Version, CURRENT_VERSION, UPDATED_LEGACY_VERSION};
use crate::{Error, ErrorKind, ProcessedPacket, Result, SphinxPacket};
use keys::RoutingKeys;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod delays;
pub mod filler;
pub mod keys;
pub mod mac;
pub mod routing;

// 32 represents size of a MontgomeryPoint on Curve25519
pub const HEADER_SIZE: usize = 32 + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct SphinxHeader {
    pub shared_secret: PublicKey,
    pub routing_info: Box<EncapsulatedRoutingInformation>,
}

pub struct ProcessedHeader {
    payload_key: PayloadKey,
    version: Version,
    data: ProcessedHeaderData,
}

pub enum ProcessedHeaderData {
    FinalHop {
        destination: DestinationAddressBytes,
        identifier: SURBIdentifier,
    },
    ForwardHop {
        updated_header: SphinxHeader,
        next_hop_address: NodeAddressBytes,
        delay: Delay,
    },
}

impl ProcessedHeader {
    pub(crate) fn payload_key(&self) -> &PayloadKey {
        &self.payload_key
    }

    pub(crate) fn attach_payload(self, payload: Payload) -> ProcessedPacket {
        match self.data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => ProcessedPacket {
                version: self.version,
                data: ProcessedPacketData::ForwardHop {
                    next_hop_packet: SphinxPacket {
                        header: updated_header,
                        payload,
                    },
                    next_hop_address,
                    delay,
                },
            },
            ProcessedHeaderData::FinalHop {
                destination,
                identifier,
            } => ProcessedPacket {
                version: self.version,
                data: ProcessedPacketData::FinalHop {
                    destination,
                    identifier,
                    payload,
                },
            },
        }
    }
}

impl SphinxHeader {
    // needs client's secret key, how should we inject this?
    // needs to deal with SURBs too at some point
    pub fn new(
        initial_secret: &StaticSecret,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
    ) -> (Self, Vec<PayloadKey>) {
        let key_material = keys::KeyMaterial::derive(route, initial_secret);
        Self::build_header(key_material, route, delays, destination, CURRENT_VERSION)
    }

    #[deprecated]
    #[allow(deprecated)]
    pub fn new_legacy(
        initial_secret: &StaticSecret,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
    ) -> (Self, Vec<PayloadKey>) {
        let key_material = keys::KeyMaterial::derive_legacy(route, initial_secret);
        Self::build_header(
            key_material,
            route,
            delays,
            destination,
            UPDATED_LEGACY_VERSION,
        )
    }

    fn build_header(
        key_material: KeyMaterial,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
        version: Version,
    ) -> (Self, Vec<PayloadKey>) {
        let filler_string = Filler::new(&key_material.routing_keys[..route.len() - 1]);
        let routing_info = Box::new(routing::EncapsulatedRoutingInformation::new(
            route,
            destination,
            delays,
            &key_material.routing_keys,
            filler_string,
            version,
        ));

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

    /// Processes the header with the provided derived keys.
    /// It could be useful in the situation where sender is re-using initial secret
    /// and we could cache processing results.
    ///
    /// However, unless you know exactly what you are doing, you should NEVER use this method!
    /// Prefer normal [process] instead.
    pub fn process_with_derived_keys(
        self,
        new_blinded_secret: &Option<PublicKey>,
        routing_keys: &RoutingKeys,
    ) -> Result<ProcessedHeader> {
        if !self.routing_info.integrity_mac.verify(
            routing_keys.header_integrity_hmac_key,
            self.routing_info.enc_routing_information.as_ref(),
        ) {
            return Err(Error::new(
                ErrorKind::InvalidHeader,
                "failed to verify integrity MAC",
            ));
        }

        let unwrapped_routing_information = self
            .routing_info
            .enc_routing_information
            .unwrap(&routing_keys.stream_cipher_key)?;
        match unwrapped_routing_information.data {
            ParsedRawRoutingInformationData::ForwardHop {
                next_hop_address,
                delay,
                new_routing_information,
            } => {
                if let Some(new_blinded_secret) = new_blinded_secret {
                    Ok(ProcessedHeader {
                        payload_key: routing_keys.payload_key,
                        version: unwrapped_routing_information.version,
                        data: ProcessedHeaderData::ForwardHop {
                            updated_header: SphinxHeader {
                                shared_secret: *new_blinded_secret,
                                routing_info: new_routing_information,
                            },
                            next_hop_address,
                            delay,
                        },
                    })
                } else {
                    Err(Error::new(
                        ErrorKind::InvalidHeader,
                        "tried to process forward hop without blinded secret",
                    ))
                }
            }
            ParsedRawRoutingInformationData::FinalHop {
                destination,
                identifier,
            } => Ok(ProcessedHeader {
                payload_key: routing_keys.payload_key,
                version: unwrapped_routing_information.version,
                data: ProcessedHeaderData::FinalHop {
                    destination,
                    identifier,
                },
            }),
        }
    }

    /// Using the provided shared_secret and node's secret key, derive all routing keys for this hop.
    pub fn compute_routing_keys(
        shared_secret: &PublicKey,
        node_secret_key: &StaticSecret,
    ) -> RoutingKeys {
        let shared_key = PublicKey::from(node_secret_key.diffie_hellman(shared_secret).to_bytes());
        keys::RoutingKeys::derive(shared_key)
    }

    fn ensure_valid_mac(&self, routing_keys: &RoutingKeys) -> Result<()> {
        if !self.routing_info.integrity_mac.verify(
            routing_keys.header_integrity_hmac_key,
            self.routing_info.enc_routing_information.as_ref(),
        ) {
            return Err(Error::new(
                ErrorKind::InvalidHeader,
                "failed to verify integrity MAC",
            ));
        }
        Ok(())
    }

    pub fn process(self, node_secret_key: &StaticSecret) -> Result<ProcessedHeader> {
        let routing_keys = Self::compute_routing_keys(&self.shared_secret, node_secret_key);
        self.ensure_valid_mac(&routing_keys)?;

        let unwrapped_routing_information = self
            .routing_info
            .enc_routing_information
            .unwrap(&routing_keys.stream_cipher_key)?;

        Ok(unwrapped_routing_information.into_processed_header(self.shared_secret, routing_keys))
    }

    #[deprecated]
    #[allow(deprecated)]
    pub fn process_legacy(self, node_secret_key: &StaticSecret) -> Result<ProcessedHeader> {
        let routing_keys = Self::compute_routing_keys(&self.shared_secret, node_secret_key);
        self.ensure_valid_mac(&routing_keys)?;

        let unwrapped_routing_information = self
            .routing_info
            .enc_routing_information
            .unwrap(&routing_keys.stream_cipher_key)?;

        Ok(unwrapped_routing_information
            .legacy_into_processed_header(self.shared_secret, routing_keys))
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
        let shared_secret = PublicKey::from(shared_secret_bytes);

        // the rest are for the encapsulated routing info
        let encapsulated_routing_info_bytes = bytes[32..HEADER_SIZE].to_vec();

        let routing_info = Box::new(EncapsulatedRoutingInformation::from_bytes(
            &encapsulated_routing_info_bytes,
        )?);

        Ok(SphinxHeader {
            shared_secret,
            routing_info,
        })
    }

    fn blind_the_shared_secret(
        shared_secret: PublicKey,
        blinding_factor: StaticSecret,
    ) -> PublicKey {
        // shared_secret * blinding_factor
        let new_shared_secret = blinding_factor.diffie_hellman(&shared_secret);
        PublicKey::from(new_shared_secret.to_bytes())
    }

    /// use unreduced multiplication for legacy backwards compatibility
    #[deprecated]
    fn legacy_blind_shared_secret(
        shared_secret: PublicKey,
        blinding_factor: StaticSecret,
    ) -> PublicKey {
        let blinding_factor =
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order(blinding_factor.to_bytes());
        let mp = curve25519_dalek::montgomery::MontgomeryPoint(shared_secret.to_bytes());
        PublicKey::from((blinding_factor * mp).to_bytes())
    }
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::{
        constants::NODE_ADDRESS_LENGTH,
        test_utils::fixtures::{destination_fixture, keygen},
    };
    use std::time::Duration;

    #[test]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let route_destination = destination_fixture();
        let initial_secret = StaticSecret::random();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let (sphinx_header, _) =
            SphinxHeader::new(&initial_secret, &route, &delays, &route_destination);

        //let (new_header, next_hop_address, _) = sphinx_header.process(node1_sk).unwrap();
        let new_header = match sphinx_header.process(&node1_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                updated_header
            }
            _ => panic!(),
        };

        let new_header2 = match new_header.process(&node2_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                updated_header
            }
            _ => panic!(),
        };
        match new_header2.process(&node3_sk).unwrap().data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier: _,
            } => {
                assert_eq!(route_destination.address, destination);
            }
            _ => panic!(),
        };
    }

    #[test]
    #[allow(deprecated)]
    fn it_returns_correct_routing_information_at_each_hop_for_route_of_3_mixnodes_with_legacy_processing(
    ) {
        let node1_sk = PrivateKey::from([
            202, 37, 190, 57, 90, 36, 148, 40, 37, 203, 207, 229, 5, 80, 8, 77, 227, 95, 67, 20,
            47, 83, 220, 34, 164, 207, 5, 212, 97, 151, 142, 168,
        ]);
        let node1_pk = PublicKey::from([
            105, 91, 210, 146, 245, 155, 27, 169, 192, 123, 75, 121, 19, 204, 59, 187, 190, 150,
            131, 118, 151, 77, 180, 144, 253, 88, 6, 212, 63, 5, 51, 7,
        ]);

        let node2_sk = PrivateKey::from([
            130, 31, 0, 83, 139, 16, 225, 239, 132, 130, 122, 18, 217, 187, 91, 87, 250, 137, 152,
            220, 254, 153, 246, 249, 252, 43, 153, 191, 152, 48, 154, 170,
        ]);
        let node2_pk = PublicKey::from([
            178, 47, 98, 179, 103, 199, 16, 245, 35, 85, 9, 63, 138, 212, 83, 233, 169, 31, 205,
            20, 73, 238, 141, 204, 19, 35, 226, 138, 44, 67, 225, 46,
        ]);

        let node3_sk = PrivateKey::from([
            116, 204, 108, 186, 75, 233, 232, 22, 79, 66, 65, 176, 196, 246, 253, 30, 133, 153,
            109, 229, 133, 177, 40, 42, 175, 72, 80, 70, 161, 7, 187, 155,
        ]);
        let node3_pk = PublicKey::from([
            21, 93, 4, 80, 178, 177, 7, 218, 192, 213, 58, 157, 239, 242, 139, 45, 75, 26, 225, 54,
            174, 21, 159, 25, 62, 87, 187, 46, 92, 246, 136, 81,
        ]);

        let node1 = Node::new(
            NodeAddressBytes::from_bytes([1u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([3u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );
        let initial_secret = StaticSecret::from([
            104, 106, 58, 28, 53, 127, 216, 216, 8, 84, 74, 171, 220, 71, 145, 25, 205, 24, 253,
            23, 120, 124, 255, 114, 14, 246, 179, 119, 101, 14, 10, 89,
        ]);

        let route = [node1, node2, node3];
        let route_destination = destination_fixture();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let (sphinx_header, _) =
            SphinxHeader::new_legacy(&initial_secret, &route, &delays, &route_destination);

        //let (new_header, next_hop_address, _) = sphinx_header.process(node1_sk).unwrap();
        let new_header = match sphinx_header.process_legacy(&node1_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                updated_header
            }
            _ => panic!(),
        };

        let new_header2 = match new_header.process_legacy(&node2_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop {
                updated_header,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([3u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                updated_header
            }
            _ => panic!(),
        };
        match new_header2.process_legacy(&node3_sk).unwrap().data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier: _,
            } => {
                assert_eq!(route_destination.address, destination);
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod unwrap_routing_information {
    use super::*;
    use crate::constants::{
        HEADER_INTEGRITY_MAC_SIZE, NODE_ADDRESS_LENGTH, NODE_META_INFO_SIZE,
        STREAM_CIPHER_OUTPUT_LENGTH,
    };
    use crate::crypto;
    use crate::header::routing::nodes::EncryptedRoutingInformation;
    use crate::header::routing::{ENCRYPTED_ROUTING_INFO_SIZE, FORWARD_HOP};
    use crate::utils;

    #[test]
    fn it_returns_correct_unwrapped_routing_information() {
        let mut routing_info = [9u8; ENCRYPTED_ROUTING_INFO_SIZE];
        routing_info[0] = FORWARD_HOP;
        // reserved 0 byte for version
        routing_info[1] = 0;

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

        let expected_next_hop_encrypted_routing_information = [
            routing_info[NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE..].to_vec(),
            pseudorandom_bytes
                [NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE..]
                .to_vec(),
        ]
        .concat();
        let next_hop_encapsulated_routing_info =
            match enc_routing_info.unwrap(&stream_cipher_key).unwrap().data {
                ParsedRawRoutingInformationData::ForwardHop {
                    next_hop_address,
                    new_routing_information,
                    ..
                } => {
                    assert_eq!(
                        routing_info[2..2 + NODE_ADDRESS_LENGTH],
                        next_hop_address.as_bytes()
                    );
                    assert_eq!(
                        routing_info
                            [NODE_ADDRESS_LENGTH..NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE]
                            .to_vec(),
                        new_routing_information.integrity_mac.as_bytes().to_vec()
                    );
                    new_routing_information
                }
                _ => panic!(),
            };

        let next_hop_encrypted_routing_information = next_hop_encapsulated_routing_info
            .enc_routing_information
            .as_ref();

        for i in 0..expected_next_hop_encrypted_routing_information.len() {
            assert_eq!(
                expected_next_hop_encrypted_routing_information[i],
                next_hop_encrypted_routing_information[i]
            );
        }
    }
}

#[cfg(test)]
mod unwrapping_using_previously_derived_keys {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::test_utils::fixtures::{destination_fixture, keygen};
    use std::time::Duration;

    #[test]
    fn produces_same_result_for_forward_hop() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let route = [node1, node2];
        let destination = destination_fixture();
        let initial_secret = StaticSecret::random();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let (sphinx_header, _) = SphinxHeader::new(&initial_secret, &route, &delays, &destination);
        let initial_secret = sphinx_header.shared_secret;

        let normally_unwrapped = match sphinx_header.clone().process(&node1_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop { updated_header, .. } => updated_header,
            _ => unreachable!(),
        };

        let new_secret = normally_unwrapped.shared_secret;
        let routing_keys = SphinxHeader::compute_routing_keys(&initial_secret, &node1_sk);

        let derived_unwrapped = match sphinx_header
            .process_with_derived_keys(&Some(new_secret), &routing_keys)
            .unwrap()
            .data
        {
            ProcessedHeaderData::ForwardHop { updated_header, .. } => updated_header,
            _ => unreachable!(),
        };

        assert_eq!(
            normally_unwrapped.shared_secret,
            derived_unwrapped.shared_secret
        );
        assert_eq!(
            normally_unwrapped.routing_info.to_bytes(),
            derived_unwrapped.routing_info.to_bytes()
        )
    }

    #[test]
    fn produces_same_result_for_final_hop() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let route = [node1];
        let destination = destination_fixture();
        let initial_secret = StaticSecret::random();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let (sphinx_header, _) = SphinxHeader::new(&initial_secret, &route, &delays, &destination);
        let initial_secret = sphinx_header.shared_secret;

        let normally_unwrapped = sphinx_header.clone().process(&node1_sk).unwrap();
        let normally_unwrapped = match normally_unwrapped.data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier,
            } => (destination, identifier, normally_unwrapped.payload_key),
            _ => unreachable!(),
        };

        let routing_keys = SphinxHeader::compute_routing_keys(&initial_secret, &node1_sk);

        let derived_unwrapped = sphinx_header
            .process_with_derived_keys(&None, &routing_keys)
            .unwrap();

        let derived_unwrapped = match derived_unwrapped.data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier,
            } => (destination, identifier, derived_unwrapped.payload_key),
            _ => unreachable!(),
        };

        assert_eq!(normally_unwrapped.0, derived_unwrapped.0);
        assert_eq!(normally_unwrapped.1, derived_unwrapped.1);
        assert_eq!(normally_unwrapped.2.to_vec(), derived_unwrapped.2.to_vec())
    }
}

#[cfg(test)]
mod converting_header_to_bytes {
    use super::*;
    use crate::test_utils::fixtures::encapsulated_routing_information_fixture;

    #[test]
    fn it_is_possible_to_convert_back_and_forth() {
        let encapsulated_routing_info = Box::new(encapsulated_routing_information_fixture());
        let header = SphinxHeader {
            shared_secret: PublicKey::from(&StaticSecret::random()),
            routing_info: encapsulated_routing_info,
        };

        let header_bytes = header.to_bytes();
        let recovered_header = SphinxHeader::from_bytes(&header_bytes).unwrap();

        assert_eq!(
            header.shared_secret.as_bytes(),
            recovered_header.shared_secret.as_bytes()
        );
        assert_eq!(
            header.routing_info.to_bytes(),
            recovered_header.routing_info.to_bytes()
        );
    }
}
