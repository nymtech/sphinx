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

use crate::constants::{
    DELAY_LENGTH, DESTINATION_ADDRESS_LENGTH, HEADER_INTEGRITY_MAC_SIZE, NODE_ADDRESS_LENGTH,
    NODE_META_INFO_SIZE, STREAM_CIPHER_OUTPUT_LENGTH, VERSION_LENGTH,
};
use crate::crypto;
use crate::crypto::STREAM_CIPHER_INIT_VECTOR;
use crate::header::delays::Delay;
use crate::header::keys::{HeaderIntegrityMacKey, StreamCipherKey};
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::{
    EncapsulatedRoutingInformation, RoutingFlag, Version, ENCRYPTED_ROUTING_INFO_SIZE, FINAL_HOP,
    FORWARD_HOP, TRUNCATED_ROUTING_INFO_SIZE,
};
use crate::route::{DestinationAddressBytes, NodeAddressBytes, SURBIdentifier};
use crate::utils;
use crate::{Error, ErrorKind, Result};
use std::fmt;

pub const PADDED_ENCRYPTED_ROUTING_INFO_SIZE: usize =
    ENCRYPTED_ROUTING_INFO_SIZE + NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE;

// in paper beta
pub(super) struct RoutingInformation {
    flag: RoutingFlag,
    version: Version,
    // in paper nu
    node_address: NodeAddressBytes,
    delay: Delay,
    // in paper gamma
    header_integrity_mac: HeaderIntegrityMac,
    // in paper also beta (!)
    next_routing_information: TruncatedRoutingInformation,
}

impl RoutingInformation {
    pub(super) fn new(
        node_address: NodeAddressBytes,
        delay: Delay,
        next_encapsulated_routing_information: EncapsulatedRoutingInformation,
    ) -> Self {
        RoutingInformation {
            flag: FORWARD_HOP,
            version: Version::new(),
            node_address,
            delay,
            header_integrity_mac: next_encapsulated_routing_information.integrity_mac,
            next_routing_information: next_encapsulated_routing_information
                .enc_routing_information
                .truncate(),
        }
    }

    fn concatenate_components(self) -> Vec<u8> {
        std::iter::once(self.flag)
            .chain(self.version.to_bytes().iter().cloned())
            .chain(self.node_address.as_bytes_ref().iter().cloned())
            .chain(self.delay.to_bytes().iter().cloned())
            .chain(self.header_integrity_mac.into_inner().into_iter())
            .chain(self.next_routing_information.iter().cloned())
            .collect()
    }

    pub(super) fn encrypt(self, key: StreamCipherKey) -> EncryptedRoutingInformation {
        let routing_info_components = self.concatenate_components();
        assert_eq!(ENCRYPTED_ROUTING_INFO_SIZE, routing_info_components.len());

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        let encrypted_routing_info_vec = utils::bytes::xor(
            &routing_info_components,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );

        let mut encrypted_routing_info = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        encrypted_routing_info.copy_from_slice(&encrypted_routing_info_vec);

        EncryptedRoutingInformation {
            value: encrypted_routing_info,
        }
    }
}

// result of xoring beta with rho (output of PRNG)
// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
pub struct EncryptedRoutingInformation {
    value: [u8; ENCRYPTED_ROUTING_INFO_SIZE],
}

impl fmt::Debug for EncryptedRoutingInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptedRoutingInformation: {{ value: {:?} }}",
            self.value.to_vec()
        )
    }
}

impl EncryptedRoutingInformation {
    pub fn from_bytes(bytes: [u8; ENCRYPTED_ROUTING_INFO_SIZE]) -> Self {
        Self { value: bytes }
    }

    fn truncate(self) -> TruncatedRoutingInformation {
        let mut truncated_routing_info = [0u8; TRUNCATED_ROUTING_INFO_SIZE];
        truncated_routing_info.copy_from_slice(&self.value[..TRUNCATED_ROUTING_INFO_SIZE]);
        truncated_routing_info
    }

    pub fn get_value_ref(&self) -> &[u8] {
        self.value.as_ref()
    }

    pub(super) fn encapsulate_with_mac(
        self,
        key: HeaderIntegrityMacKey,
    ) -> EncapsulatedRoutingInformation {
        let integrity_mac = HeaderIntegrityMac::compute(key, &self.value);
        EncapsulatedRoutingInformation {
            enc_routing_information: self,
            integrity_mac,
        }
    }

    fn add_zero_padding(self) -> PaddedEncryptedRoutingInformation {
        let zero_bytes =
            std::iter::repeat(0u8).take(NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE);
        let padded_enc_routing_info: Vec<u8> =
            self.value.iter().cloned().chain(zero_bytes).collect();

        assert_eq!(
            PADDED_ENCRYPTED_ROUTING_INFO_SIZE,
            padded_enc_routing_info.len()
        );
        PaddedEncryptedRoutingInformation {
            value: padded_enc_routing_info,
        }
    }

    pub(crate) fn unwrap(
        self,
        stream_cipher_key: StreamCipherKey,
    ) -> Result<ParsedRawRoutingInformation> {
        // we have to add padding to the encrypted routing information before decrypting, otherwise we gonna lose information
        self.add_zero_padding().decrypt(stream_cipher_key).parse()
    }
}

pub struct PaddedEncryptedRoutingInformation {
    value: Vec<u8>,
}

impl PaddedEncryptedRoutingInformation {
    pub fn decrypt(self, key: StreamCipherKey) -> RawRoutingInformation {
        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &key,
            &crypto::STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        assert_eq!(self.value.len(), pseudorandom_bytes.len());
        RawRoutingInformation {
            value: utils::bytes::xor(&self.value, &pseudorandom_bytes),
        }
    }
}

pub struct RawRoutingInformation {
    value: Vec<u8>,
}

pub enum ParsedRawRoutingInformation {
    ForwardHop(NodeAddressBytes, Delay, Box<EncapsulatedRoutingInformation>),
    FinalHop(DestinationAddressBytes, SURBIdentifier),
}

impl RawRoutingInformation {
    pub fn parse(self) -> Result<ParsedRawRoutingInformation> {
        assert_eq!(
            NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE,
            self.value.len()
        );

        let flag = self.value[0];
        match flag {
            FORWARD_HOP => Ok(self.parse_as_forward_hop()),
            FINAL_HOP => Ok(self.parse_as_final_hop()),
            _ => Err(Error::new(
                ErrorKind::InvalidRouting,
                format!("tried to parse unknown routing flag: {}", flag),
            )),
        }
    }

    fn parse_as_forward_hop(self) -> ParsedRawRoutingInformation {
        let mut i = 1;

        let mut version: [u8; VERSION_LENGTH] = Default::default();
        version.copy_from_slice(&self.value[i..i + VERSION_LENGTH]);
        i += VERSION_LENGTH;

        let mut next_hop_address: [u8; NODE_ADDRESS_LENGTH] = Default::default();
        next_hop_address.copy_from_slice(&self.value[i..i + NODE_ADDRESS_LENGTH]);
        i += NODE_ADDRESS_LENGTH;

        let mut delay_bytes: [u8; DELAY_LENGTH] = Default::default();
        delay_bytes.copy_from_slice(&self.value[i..i + DELAY_LENGTH]);
        i += DELAY_LENGTH;

        // the next HEADER_INTEGRITY_MAC_SIZE bytes represent the integrity mac on the next hop
        let mut next_hop_integrity_mac: [u8; HEADER_INTEGRITY_MAC_SIZE] = Default::default();
        next_hop_integrity_mac.copy_from_slice(&self.value[i..i + HEADER_INTEGRITY_MAC_SIZE]);
        i += HEADER_INTEGRITY_MAC_SIZE;

        // the next ENCRYPTED_ROUTING_INFO_SIZE bytes represent the routing information for the next hop
        let mut next_hop_encrypted_routing_information = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        next_hop_encrypted_routing_information
            .copy_from_slice(&self.value[i..i + ENCRYPTED_ROUTING_INFO_SIZE]);

        let next_hop_encapsulated_routing_info = EncapsulatedRoutingInformation::encapsulate(
            EncryptedRoutingInformation::from_bytes(next_hop_encrypted_routing_information),
            HeaderIntegrityMac::from_bytes(next_hop_integrity_mac),
        );

        ParsedRawRoutingInformation::ForwardHop(
            NodeAddressBytes::from_bytes(next_hop_address),
            Delay::from_bytes(delay_bytes),
            Box::new(next_hop_encapsulated_routing_info),
        )
    }

    // TODO: this needs to be updated as a correct parse as final hop function!
    fn parse_as_final_hop(self) -> ParsedRawRoutingInformation {
        let mut i = 1;

        let mut version: [u8; VERSION_LENGTH] = Default::default();
        version.copy_from_slice(&self.value[i..i + VERSION_LENGTH]);
        i += VERSION_LENGTH;

        let mut destination_bytes: [u8; DESTINATION_ADDRESS_LENGTH] = Default::default();
        destination_bytes.copy_from_slice(&self.value[i..i + DESTINATION_ADDRESS_LENGTH]);
        i += DESTINATION_ADDRESS_LENGTH;
        let destination = DestinationAddressBytes::from_bytes(destination_bytes);

        // the next HEADER_INTEGRITY_MAC_SIZE bytes represent the integrity mac on the next hop
        let mut identifier: [u8; HEADER_INTEGRITY_MAC_SIZE] = Default::default();
        identifier.copy_from_slice(&self.value[i..i + HEADER_INTEGRITY_MAC_SIZE]);

        ParsedRawRoutingInformation::FinalHop(destination, identifier)
    }
}

// result of truncating encrypted beta before passing it to next 'layer'
type TruncatedRoutingInformation = [u8; TRUNCATED_ROUTING_INFO_SIZE];

#[cfg(test)]
mod preparing_header_layer {
    use super::*;
    use crate::constants::HeaderIntegrityHmacAlgorithm;
    use crate::{
        constants::HEADER_INTEGRITY_MAC_SIZE,
        test_utils::fixtures::{
            encapsulated_routing_information_fixture, node_address_fixture, routing_keys_fixture,
        },
    };

    #[test]
    fn it_returns_encrypted_truncated_address_and_flag_concatenated_with_inner_layer_and_mac_on_it()
    {
        let node_address = node_address_fixture();
        let delay = Delay::new_from_nanos(10);
        let previous_node_routing_keys = routing_keys_fixture();
        let inner_layer_routing = encapsulated_routing_information_fixture();

        let version = Version::new();
        // calculate everything without using any object methods
        let concatenated_materials: Vec<u8> = [
            vec![FORWARD_HOP],
            version.to_bytes().to_vec(),
            node_address.as_bytes().to_vec(),
            delay.to_bytes().to_vec(),
            inner_layer_routing.integrity_mac.as_bytes().to_vec(),
            inner_layer_routing
                .enc_routing_information
                .value
                .to_vec()
                .iter()
                .cloned()
                .take(TRUNCATED_ROUTING_INFO_SIZE)
                .collect(),
        ]
        .concat();

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &previous_node_routing_keys.stream_cipher_key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        let expected_encrypted_routing_info_vec = utils::bytes::xor(
            &concatenated_materials,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );

        let expected_routing_mac = crypto::compute_keyed_hmac::<HeaderIntegrityHmacAlgorithm>(
            &previous_node_routing_keys.header_integrity_hmac_key,
            &expected_encrypted_routing_info_vec,
        );
        let mut expected_routing_mac = expected_routing_mac.into_bytes().to_vec();
        expected_routing_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);

        let next_layer_routing = RoutingInformation::new(node_address, delay, inner_layer_routing)
            .encrypt(previous_node_routing_keys.stream_cipher_key)
            .encapsulate_with_mac(previous_node_routing_keys.header_integrity_hmac_key);

        assert_eq!(
            expected_encrypted_routing_info_vec,
            next_layer_routing.enc_routing_information.value.to_vec()
        );
        assert_eq!(
            expected_routing_mac,
            next_layer_routing.integrity_mac.as_bytes().to_vec()
        );
    }
}

#[cfg(test)]
mod encrypting_routing_information {
    use super::*;
    use crate::{
        crypto::STREAM_CIPHER_KEY_SIZE,
        test_utils::fixtures::{header_integrity_mac_fixture, node_address_fixture},
    };

    #[test]
    fn it_is_possible_to_decrypt_it_to_recover_original_data() {
        let key = [2u8; STREAM_CIPHER_KEY_SIZE];
        let flag = FORWARD_HOP;
        let address = node_address_fixture();
        let delay = Delay::new_from_nanos(15);
        let mac = header_integrity_mac_fixture();
        let next_routing = [8u8; TRUNCATED_ROUTING_INFO_SIZE];

        let version = Version::new();
        let encryption_data = [
            vec![flag],
            version.to_bytes().to_vec(),
            address.as_bytes().to_vec(),
            delay.to_bytes().to_vec(),
            mac.as_bytes().to_vec(),
            next_routing.to_vec(),
        ]
        .concat();

        let routing_information = RoutingInformation {
            flag: FORWARD_HOP,
            version,
            node_address: address,
            delay,
            header_integrity_mac: mac,
            next_routing_information: next_routing,
        };

        let encrypted_data = routing_information.encrypt(key);
        let decryption_key_source = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let decryption_key = &decryption_key_source[..ENCRYPTED_ROUTING_INFO_SIZE];
        let decrypted_data = utils::bytes::xor(&encrypted_data.value, decryption_key);
        assert_eq!(encryption_data, decrypted_data);
    }
}

#[cfg(test)]
mod truncating_routing_information {
    use crate::test_utils::fixtures::encrypted_routing_information_fixture;

    #[test]
    fn it_does_not_change_prefixed_data() {
        let encrypted_routing_info = encrypted_routing_information_fixture();
        let routing_info_data_copy = encrypted_routing_info.value;

        let truncated_routing_info = encrypted_routing_info.truncate();
        for i in 0..truncated_routing_info.len() {
            assert_eq!(truncated_routing_info[i], routing_info_data_copy[i]);
        }
    }
}

#[cfg(test)]
mod parse_decrypted_routing_information {
    use super::*;
    use crate::{
        header::routing::ENCRYPTED_ROUTING_INFO_SIZE,
        test_utils::fixtures::{header_integrity_mac_fixture, node_address_fixture},
    };

    #[test]
    fn it_returns_next_hop_address_integrity_mac_enc_routing_info() {
        let flag = FORWARD_HOP;
        let address_fixture = node_address_fixture();
        let delay = Delay::new_from_nanos(10);
        let integrity_mac = header_integrity_mac_fixture();
        let next_routing_information = [1u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let version = Version::new();

        let data = [
            vec![flag],
            version.to_bytes().to_vec(),
            address_fixture.as_bytes().to_vec(),
            delay.to_bytes().to_vec(),
            integrity_mac.as_bytes().to_vec(),
            next_routing_information.to_vec(),
        ]
        .concat();

        let raw_routing_info = RawRoutingInformation { value: data };

        match raw_routing_info.parse().unwrap() {
            ParsedRawRoutingInformation::ForwardHop(
                next_address,
                _delay,
                encapsulated_routing_info,
            ) => {
                assert_eq!(address_fixture, next_address);
                assert_eq!(
                    integrity_mac.as_bytes().to_vec(),
                    encapsulated_routing_info.integrity_mac.as_bytes().to_vec()
                );
                assert_eq!(
                    next_routing_information.to_vec(),
                    encapsulated_routing_info
                        .enc_routing_information
                        .get_value_ref()
                        .to_vec()
                );
            }
            ParsedRawRoutingInformation::FinalHop(_, _) => panic!(),
        }
    }
}
