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
    route::{Node, NodeAddressBytes},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod fixtures {
    use crate::header::shared_secret::{expand_shared_secret, ExpandedSharedSecret};
    use crate::test_utils::test_rng;
    use crate::{
        constants::{
            DESTINATION_ADDRESS_LENGTH, HEADER_INTEGRITY_MAC_SIZE, IDENTIFIER_LENGTH,
            NODE_ADDRESS_LENGTH,
        },
        header::{
            filler::{Filler, FILLER_STEP_SIZE_INCREASE},
            mac::HeaderIntegrityMac,
            routing::{
                nodes::EncryptedRoutingInformation, EncapsulatedRoutingInformation,
                ENCRYPTED_ROUTING_INFO_SIZE,
            },
        },
        route::{Destination, DestinationAddressBytes, NodeAddressBytes, SURBIdentifier},
    };
    use rand_chacha::ChaCha20Rng;
    use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

    pub(crate) fn mock_shared_secret(mut rng: &mut ChaCha20Rng) -> SharedSecret {
        let sk1 = StaticSecret::random_from_rng(&mut rng);
        let pk1 = PublicKey::from(&sk1);

        let sk2 = StaticSecret::random_from_rng(&mut rng);
        sk2.diffie_hellman(&pk1)
    }

    pub fn expanded_shared_secret_fixture() -> ExpandedSharedSecret {
        let mut rng = test_rng();
        let ss = mock_shared_secret(&mut rng);
        expand_shared_secret(ss.as_bytes())
    }

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

    pub fn filler_fixture(i: usize) -> Filler {
        Filler::from(vec![9u8; FILLER_STEP_SIZE_INCREASE * i])
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

    pub fn keygen() -> (StaticSecret, PublicKey) {
        let private_key = StaticSecret::random();
        let public_key = PublicKey::from(&private_key);
        (private_key, public_key)
    }
}

pub fn random_node() -> Node {
    let random_private_key = x25519_dalek::EphemeralSecret::random();
    Node {
        address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
        pub_key: (&random_private_key).into(),
    }
}

// make sure output is deterministic
pub(super) fn test_rng() -> ChaCha20Rng {
    let dummy_seed = [42u8; 32];
    seeded_rng(dummy_seed)
}

pub(super) fn seeded_rng(seed: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed)
}

pub(crate) fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

pub(crate) fn assert_zeroize<T: Zeroize>() {}
