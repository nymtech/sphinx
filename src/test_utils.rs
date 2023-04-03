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

use crate::{
    constants::NODE_ADDRESS_LENGTH,
    crypto,
    route::{Node, NodeAddressBytes},
};

pub mod fixtures {

    use crate::crypto::EphemeralSecret;
    use crate::{
        constants::{
            BLINDING_FACTOR_SIZE, DESTINATION_ADDRESS_LENGTH, HEADER_INTEGRITY_MAC_SIZE,
            IDENTIFIER_LENGTH, INTEGRITY_MAC_KEY_SIZE, NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SIZE,
        },
        crypto,
        header::{
            filler::{Filler, FILLER_STEP_SIZE_INCREASE},
            keys::RoutingKeys,
            mac::HeaderIntegrityMac,
            routing::{
                nodes::EncryptedRoutingInformation, EncapsulatedRoutingInformation,
                ENCRYPTED_ROUTING_INFO_SIZE,
            },
        },
        route::{Destination, DestinationAddressBytes, NodeAddressBytes, SURBIdentifier},
    };

    pub fn destination_address_fixture() -> DestinationAddressBytes {
        DestinationAddressBytes::from_bytes([1u8; DESTINATION_ADDRESS_LENGTH])
    }

    pub fn node_address_fixture() -> NodeAddressBytes {
        NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH])
    }

    pub fn surb_identifier_fixture() -> SURBIdentifier {
        [5u8; IDENTIFIER_LENGTH]
    }

    pub fn destination_fixture() -> Destination {
        Destination {
            address: DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            identifier: [4u8; IDENTIFIER_LENGTH],
        }
    }

    pub fn routing_keys_fixture() -> RoutingKeys {
        RoutingKeys {
            stream_cipher_key: [1u8; crypto::STREAM_CIPHER_KEY_SIZE],
            header_integrity_hmac_key: [2u8; INTEGRITY_MAC_KEY_SIZE],
            payload_key: [3u8; PAYLOAD_KEY_SIZE],
            blinding_factor: EphemeralSecret::from_scalar_bytes([4u8; BLINDING_FACTOR_SIZE]),
        }
    }

    pub fn filler_fixture(i: usize) -> Filler {
        Filler::from_raw(vec![9u8; FILLER_STEP_SIZE_INCREASE * i])
    }

    pub fn encrypted_routing_information_fixture() -> EncryptedRoutingInformation {
        EncryptedRoutingInformation::from_bytes([5u8; ENCRYPTED_ROUTING_INFO_SIZE])
    }

    pub fn header_integrity_mac_fixture() -> HeaderIntegrityMac {
        HeaderIntegrityMac::from_bytes([6u8; HEADER_INTEGRITY_MAC_SIZE])
    }

    pub fn encapsulated_routing_information_fixture() -> EncapsulatedRoutingInformation {
        EncapsulatedRoutingInformation {
            enc_routing_information: encrypted_routing_information_fixture(),
            integrity_mac: header_integrity_mac_fixture(),
        }
    }
}

pub fn random_node() -> Node {
    let random_private_key = crypto::PrivateKey::new();
    Node {
        address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
        pub_key: (&random_private_key).into(),
    }
}
