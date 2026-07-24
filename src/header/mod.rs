// Copyright 2020-2025 Nym Technologies SA
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
use crate::header::keys::KeyMaterial;
use crate::header::routing::{EncapsulatedRoutingInformation, ENCRYPTED_ROUTING_INFO_SIZE};
use crate::header::shared_secret::{ExpandSecret, ExpandedSharedSecret};
use crate::packet::ProcessedPacketData;
use crate::payload::key::{derive_payload_key, PayloadKey, PayloadKeySeed};
use crate::payload::Payload;
use crate::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier};
use crate::version::Version;
use crate::{Error, ErrorKind, ProcessedPacket, Result, SphinxPacket};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod delays;
pub mod filler;
pub mod keys;
pub mod mac;
pub mod routing;
pub mod shared_secret;

// 32 represents size of a MontgomeryPoint on Curve25519
pub const HEADER_SIZE: usize = 32 + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct SphinxHeader {
    /// Alpha element
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
    #[cfg(test)]
    pub(crate) fn new_current(
        initial_secret: &StaticSecret,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
    ) -> BuiltHeader {
        let key_material = keys::KeyMaterial::derive(route, initial_secret);
        Self::build_header(
            key_material,
            route,
            delays,
            destination,
            crate::version::CURRENT_VERSION,
        )
    }

    pub(crate) fn new_versioned(
        initial_secret: &StaticSecret,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
        version: Version,
    ) -> BuiltHeader {
        let key_material = keys::KeyMaterial::derive(route, initial_secret);
        Self::build_header(key_material, route, delays, destination, version)
    }

    fn build_header(
        key_material: KeyMaterial,
        route: &[Node],
        delays: &[Delay],
        destination: &Destination,
        version: Version,
    ) -> BuiltHeader {
        let filler_string = Filler::new(&key_material.expanded_shared_secrets[..route.len() - 1]);
        let routing_info = EncapsulatedRoutingInformation::new(
            route,
            destination,
            delays,
            &key_material.expanded_shared_secrets,
            filler_string,
            version,
        );

        // encapsulate header.routing information, compute MACs
        BuiltHeader::new(version, key_material, routing_info)
    }

    // note: this method is currently removed because there's too many branches to support
    // with the legacy compatibility requirements.
    // this will be revisited in the future
    // /// Processes the header with the provided shared secret
    // /// It could be useful in the situation where sender is re-using initial secret
    // /// and we could cache processing results.
    // ///
    // /// However, unless you know exactly what you are doing, you should NEVER use this method!
    // /// Prefer normal [process] instead.
    // pub fn process_with_cached_secret(
    //     &self,
    //     expanded_secret: ExpandedSharedSecret,
    //     cached_new_shared_secret: PublicKey,
    // ) -> Result<ProcessedHeader> {
    //     self.ensure_valid_mac(expanded_secret.header_integrity_hmac_key())?;
    //
    //     let unwrapped_routing_information = self
    //         .routing_info
    //         .enc_routing_information
    //         .unwrap(expanded_secret.stream_cipher_key())?;
    //
    //     match unwrapped_routing_information.data {
    //         ParsedRawRoutingInformationData::ForwardHop {
    //             next_hop_address,
    //             delay,
    //             new_routing_information,
    //         } => {
    //             if let Some(new_blinded_secret) = cached_new_derived_secret {
    //                 Ok(ProcessedHeader {
    //                     payload_key: *expanded_secret.payload_key(),
    //                     version: unwrapped_routing_information.version,
    //                     data: ProcessedHeaderData::ForwardHop {
    //                         updated_header: SphinxHeader {
    //                             shared_secret: new_blinded_secret,
    //                             routing_info: new_routing_information,
    //                         },
    //                         next_hop_address,
    //                         delay,
    //                     },
    //                 })
    //             } else {
    //                 Err(Error::new(
    //                     ErrorKind::InvalidHeader,
    //                     "tried to process forward hop without blinded secret",
    //                 ))
    //             }
    //         }
    //         ParsedRawRoutingInformationData::FinalHop {
    //             destination,
    //             identifier,
    //         } => Ok(ProcessedHeader {
    //             payload_key: *expanded_secret.payload_key(),
    //             version: unwrapped_routing_information.version,
    //             data: ProcessedHeaderData::FinalHop {
    //                 destination,
    //                 identifier,
    //             },
    //         }),
    //     }
    // }

    /// Processes the header with the provided expanded shared secret
    /// It could be useful in the situation where caller has already derived the value,
    /// because, for example, he had to obtain the reply tag.
    #[allow(deprecated)]
    pub fn process_with_expanded_secret(
        self,
        expanded_secret: &ExpandedSharedSecret,
    ) -> Result<ProcessedHeader> {
        self.ensure_header_integrity(expanded_secret)?;

        let unwrapped_routing_information = self
            .routing_info
            .enc_routing_information
            .unwrap(expanded_secret.stream_cipher_key())?;

        Ok(
            unwrapped_routing_information
                .into_processed_header(self.shared_secret, expanded_secret),
        )
    }

    #[allow(deprecated)]
    pub fn process(self, node_secret_key: &StaticSecret) -> Result<ProcessedHeader> {
        let expanded_secret = self.compute_expanded_shared_secret(node_secret_key);
        self.process_with_expanded_secret(&expanded_secret)
    }

    /// Using the provided packet's alpha and node's secret key, expand it into the output of all required random oracles
    pub fn compute_expanded_shared_secret(
        &self,
        node_secret_key: &StaticSecret,
    ) -> ExpandedSharedSecret {
        node_secret_key
            .diffie_hellman(&self.shared_secret)
            .expand_shared_secret()
    }

    pub fn ensure_header_integrity(
        &self,
        expanded_shared_secret: &ExpandedSharedSecret,
    ) -> Result<()> {
        if !self.routing_info.integrity_mac.verify(
            expanded_shared_secret.header_integrity_hmac_key(),
            self.routing_info.enc_routing_information.as_ref(),
        ) {
            return Err(Error::new(
                ErrorKind::InvalidHeader,
                "failed to verify integrity MAC",
            ));
        }
        Ok(())
    }

    #[deprecated]
    pub fn unchecked_process_as_current(
        self,
        node_secret_key: &StaticSecret,
    ) -> Result<ProcessedHeader> {
        let expanded_secret = self.compute_expanded_shared_secret(node_secret_key);
        self.ensure_header_integrity(&expanded_secret)?;

        let unwrapped_routing_information = self
            .routing_info
            .enc_routing_information
            .unwrap(expanded_secret.stream_cipher_key())?;

        Ok(unwrapped_routing_information
            .into_processed_header(self.shared_secret, &expanded_secret))
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
        let routing_info = Box::new(EncapsulatedRoutingInformation::from_bytes(&bytes[32..])?);

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
}

pub(crate) struct BuiltHeader {
    header: SphinxHeader,
    version: Version,
    expanded_secrets: Vec<ExpandedSharedSecret>,
}

impl BuiltHeader {
    fn new(
        version: Version,
        key_material: KeyMaterial,
        routing_information: EncapsulatedRoutingInformation,
    ) -> Self {
        BuiltHeader {
            header: SphinxHeader {
                shared_secret: key_material.initial_shared_secret,
                routing_info: Box::new(routing_information),
            },
            version,
            expanded_secrets: key_material.expanded_shared_secrets,
        }
    }

    // depending on the version either use the initial hkdf output as payload keys
    // or extract the seed and run it through another hkdf
    pub(crate) fn derive_payload_keys(&self) -> Vec<PayloadKey> {
        if self.version.expects_legacy_full_payload_keys() {
            self.legacy_full_payload_keys()
        } else {
            self.expanded_secrets
                .iter()
                .map(|s| derive_payload_key(s.payload_key_seed()))
                .collect()
        }
    }

    pub(crate) fn legacy_full_payload_keys(&self) -> Vec<PayloadKey> {
        self.expanded_secrets
            .iter()
            .map(|s| *s.legacy_payload_key())
            .collect()
    }

    pub(crate) fn payload_key_seeds(&self) -> Vec<PayloadKeySeed> {
        self.expanded_secrets
            .iter()
            .map(|s| *s.payload_key_seed())
            .collect()
    }

    pub(crate) fn into_header(self) -> SphinxHeader {
        self.header
    }
}

#[cfg(test)]
mod create_and_process_sphinx_packet_header {
    use super::*;
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
        let sphinx_header =
            SphinxHeader::new_current(&initial_secret, &route, &delays, &route_destination)
                .into_header();

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
}

#[cfg(test)]
mod unwrap_routing_information {
    use crate::constants::{
        HEADER_INTEGRITY_MAC_SIZE, NODE_ADDRESS_LENGTH, NODE_META_INFO_SIZE,
        STREAM_CIPHER_OUTPUT_LENGTH,
    };
    use crate::crypto;
    use crate::header::routing::nodes::{
        EncryptedRoutingInformation, ParsedRawRoutingInformationData,
    };
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
                        next_hop_address.to_bytes()
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
mod unwrapping_using_previously_expanded_shared_secret {
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
        let sphinx_header =
            SphinxHeader::new_current(&initial_secret, &route, &delays, &destination).into_header();
        let initial_secret = sphinx_header.shared_secret;

        let normally_unwrapped = match sphinx_header.clone().process(&node1_sk).unwrap().data {
            ProcessedHeaderData::ForwardHop { updated_header, .. } => updated_header,
            _ => unreachable!(),
        };

        let expanded_secret = node1_sk
            .diffie_hellman(&initial_secret)
            .expand_shared_secret();

        let derived_unwrapped = match sphinx_header
            .process_with_expanded_secret(&expanded_secret)
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
        let sphinx_header =
            SphinxHeader::new_current(&initial_secret, &route, &delays, &destination).into_header();
        let initial_secret = sphinx_header.shared_secret;

        let normally_unwrapped = sphinx_header.clone().process(&node1_sk).unwrap();
        let normally_unwrapped = match normally_unwrapped.data {
            ProcessedHeaderData::FinalHop {
                destination,
                identifier,
            } => (destination, identifier, normally_unwrapped.payload_key),
            _ => unreachable!(),
        };

        let expanded_secret = node1_sk
            .diffie_hellman(&initial_secret)
            .expand_shared_secret();

        let derived_unwrapped = sphinx_header
            .process_with_expanded_secret(&expanded_secret)
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
