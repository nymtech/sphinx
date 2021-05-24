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

use std::fmt;
use std::str;

use curve25519_dalek::scalar::Scalar;

use crate::constants::{
    BLINDING_FACTOR_SIZE, HKDF_INPUT_SEED, INTEGRITY_MAC_KEY_SIZE, PAYLOAD_KEY_SIZE,
    ROUTING_KEYS_LENGTH,
};
use crate::crypto::{self, EphemeralSecret};
use crate::crypto::{SharedKey, STREAM_CIPHER_KEY_SIZE};
use crate::header::HkdfSalt;
use crate::route::Node;

pub type StreamCipherKey = [u8; STREAM_CIPHER_KEY_SIZE];
pub type HeaderIntegrityMacKey = [u8; INTEGRITY_MAC_KEY_SIZE];
// TODO: perhaps change PayloadKey to a Vec considering it's almost 200 bytes long?
// we will lose length assertions but won't need to copy all that data every single function call
pub type PayloadKey = [u8; PAYLOAD_KEY_SIZE];
pub type BlindingFactor = [u8; BLINDING_FACTOR_SIZE];

#[derive(Clone)]
pub struct RoutingKeys {
    pub stream_cipher_key: StreamCipherKey,
    pub header_integrity_hmac_key: HeaderIntegrityMacKey,
    pub payload_key: PayloadKey,
}

impl RoutingKeys {
    // or should this be renamed to 'new'?
    // Given that everything here except RoutingKeys lives in the `crypto` module, I think
    // that this one could potentially move most of its functionality there quite profitably.
    pub fn derive(shared_key: crypto::SharedKey, salt: &HkdfSalt) -> Self {
        let mut output = [0u8; ROUTING_KEYS_LENGTH];
        let context_string: &str = match str::from_utf8(HKDF_INPUT_SEED) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        let mut salted_shared_key = [0; 64];
        let (left, right) = salted_shared_key.split_at_mut(32);
        left.copy_from_slice(&salt[..]);
        right.copy_from_slice(&shared_key.as_bytes()[..]);

        blake3::derive_key(context_string, &salted_shared_key, &mut output);

        let mut i = 0;
        let mut stream_cipher_key: [u8; crypto::STREAM_CIPHER_KEY_SIZE] = Default::default();
        stream_cipher_key.copy_from_slice(&output[i..i + crypto::STREAM_CIPHER_KEY_SIZE]);
        i += crypto::STREAM_CIPHER_KEY_SIZE;

        let mut header_integrity_hmac_key: [u8; INTEGRITY_MAC_KEY_SIZE] = Default::default();
        header_integrity_hmac_key.copy_from_slice(&output[i..i + INTEGRITY_MAC_KEY_SIZE]);
        i += INTEGRITY_MAC_KEY_SIZE;

        let mut payload_key: [u8; PAYLOAD_KEY_SIZE] = [0u8; PAYLOAD_KEY_SIZE];
        payload_key.copy_from_slice(&output[i..i + PAYLOAD_KEY_SIZE]);
        i += PAYLOAD_KEY_SIZE;

        Self {
            stream_cipher_key,
            header_integrity_hmac_key,
            payload_key,
        }
    }

    pub fn derive_routing_keys(
        shared_keys: &[SharedKey],
        hkdf_salt: &[HkdfSalt],
    ) -> Vec<RoutingKeys> {
        let mut routing_keys: Vec<RoutingKeys> = Vec::with_capacity(shared_keys.len());
        for (key, salt) in shared_keys.iter().zip(hkdf_salt.iter()) {
            let node_routing_keys = Self::derive(*key, salt);
            routing_keys.push(node_routing_keys)
        }
        routing_keys
    }
}

impl fmt::Debug for RoutingKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} {:?} {:?}",
            self.stream_cipher_key,
            self.header_integrity_hmac_key,
            self.payload_key.to_vec()
        )
    }
}

impl PartialEq for RoutingKeys {
    fn eq(&self, other: &RoutingKeys) -> bool {
        self.stream_cipher_key == other.stream_cipher_key
            && self.header_integrity_hmac_key == other.header_integrity_hmac_key
            && self.payload_key.to_vec() == other.payload_key.to_vec()
    }
}

pub struct KeyMaterial {
    pub initial_shared_group_element: crypto::SharedGroupElement,
    pub shared_keys: Vec<SharedKey>,
}

impl KeyMaterial {
    // derive shared keys, group elements, blinding factors
    pub fn derive_shared_keys(route: &[Node], initial_secret: &EphemeralSecret) -> Self {
        let mut shared_keys: Vec<SharedKey> = Vec::with_capacity(route.len());

        let mut accumulator = initial_secret.clone();
        for (i, node) in route.iter().enumerate() {
            // pub^{a * b * ...}
            let shared_key = accumulator.diffie_hellman(&node.pub_key);

            // it's not the last iteration
            if i != route.len() + 1 {
                let blinding_factor_scalar = Self::compute_blinding_factor(shared_key);
                accumulator *= &blinding_factor_scalar;
            }

            shared_keys.push(shared_key);
        }

        Self {
            shared_keys,
            initial_shared_group_element: crypto::SharedGroupElement::from(initial_secret),
        }
    }

    pub fn compute_blinding_factor(shared_key: SharedKey) -> Scalar {
        let mut blinding_factor = [0u8; BLINDING_FACTOR_SIZE];
        let context_string: &str = match str::from_utf8(HKDF_INPUT_SEED) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        blake3::derive_key(context_string, shared_key.as_bytes(), &mut blinding_factor);

        // TODO: do we need to make the reduction here or could we get away with clamping or even nothing at all?
        // considering (I *think*) proper reductions will happen during scalar multiplication, i.e. g^x?
        // So far it *seems* to produce correct result, but could it be the case it introduces
        // some vulnerabilities? Need some ECC expert here.

        // performs montgomery reduction
        let blinding_factor_scalar = Scalar::from_bytes_mod_order(blinding_factor);
        // alternatives:

        // 'only' clamps the scalar
        // let blinding_factor_scalar = crypto::clamp_scalar_bytes(node_routing_keys.blinding_factor);

        // 'only' makes it 255 bit long
        // let blinding_factor_scalar = Scalar::from_bits(node_routing_keys.blinding_factor);
        blinding_factor_scalar
    }
}

#[cfg(test)]
mod deriving_key_material {
    use crate::route::Node;

    use super::*;

    #[cfg(test)]
    mod with_an_empty_route {
        use super::*;

        #[test]
        fn it_returns_no_shared_keys() {
            let empty_route: Vec<Node> = vec![];
            let initial_secret = EphemeralSecret::new();
            let hacky_secret_copy = EphemeralSecret::from(initial_secret.to_bytes());

            let key_material = KeyMaterial::derive_shared_keys(&empty_route, &initial_secret);
            assert_eq!(0, key_material.shared_keys.len());
            assert_eq!(
                crypto::SharedKey::from(&hacky_secret_copy).as_bytes(),
                key_material.initial_shared_group_element.as_bytes()
            )
        }
    }

    #[cfg(test)]
    mod for_a_route_with_3_forward_hops {
        use crate::test_utils::random_node;

        use super::*;

        fn setup() -> (Vec<Node>, EphemeralSecret, KeyMaterial) {
            let route: Vec<Node> = vec![random_node(), random_node(), random_node()];
            let initial_secret = EphemeralSecret::new();
            let hacky_secret_copy = EphemeralSecret::from(initial_secret.to_bytes());

            let key_material = KeyMaterial::derive_shared_keys(&route, &initial_secret);
            (route, hacky_secret_copy, key_material)
        }

        #[test]
        fn it_returns_number_of_shared_keys_equal_to_length_of_the_route() {
            let (_, _, key_material) = setup();
            assert_eq!(3, key_material.shared_keys.len());
        }

        #[test]
        fn it_returns_correctly_inited_shared_secret() {
            let (_, initial_secret, key_material) = setup();
            assert_eq!(
                crypto::SharedKey::from(&initial_secret).as_bytes(),
                key_material.initial_shared_group_element.as_bytes()
            );
        }
        #[test]
        fn it_generates_correct_shared_keys() {
            let (route, initial_secret, key_material) = setup();
            let (route, initial_secret, key_material) = setup();
            // The accumulator is the key to our blinding factors working.
            // If the accumulator value isn't incremented correctly, we risk passing an
            // incorrectly blinded shared key through the mixnet in the (unencrypted)
            // Sphinx packet header. So this test ensures that the accumulator gets incremented
            // properly on each run through the loop.
            let mut expected_accumulator = initial_secret;
            for (i, node) in route.iter().enumerate() {
                let expected_shared_key = expected_accumulator.diffie_hellman(&node.pub_key);
                let expected_blinding_factor =
                    KeyMaterial::compute_blinding_factor(expected_shared_key);
                expected_accumulator *= &expected_blinding_factor;
                assert_eq!(expected_shared_key, key_material.shared_keys[i])
            }
        }
    }
}

#[cfg(test)]
mod key_derivation_function {
    use super::*;
    use crate::constants::HKDF_SALT_SIZE;
    use crate::test_utils::fixtures::hkdf_salt_fixture;

    #[test]
    fn it_expands_the_seed_key_to_expected_length() {
        let initial_secret = EphemeralSecret::new();
        let shared_key = crypto::SharedKey::from(&initial_secret);
        let routing_keys = RoutingKeys::derive(shared_key, &hkdf_salt_fixture());
        assert_eq!(
            crypto::STREAM_CIPHER_KEY_SIZE,
            routing_keys.stream_cipher_key.len()
        );
    }

    #[test]
    fn it_returns_the_same_output_for_two_equal_inputs() {
        let initial_secret = EphemeralSecret::new();
        let shared_key = crypto::SharedKey::from(&initial_secret);
        let hkdf_salt = hkdf_salt_fixture();
        let routing_keys1 = RoutingKeys::derive(shared_key, &hkdf_salt);
        let routing_keys2 = RoutingKeys::derive(shared_key, &hkdf_salt);
        assert_eq!(routing_keys1, routing_keys2);
    }
    #[test]
    fn it_returns_different_output_for_two_equal_shared_keys_and_different_salt() {
        let initial_secret = EphemeralSecret::new();
        let shared_key = crypto::SharedKey::from(&initial_secret);
        let hkdf_salt1 = [123u8; HKDF_SALT_SIZE];
        let hkdf_salt2 = [98u8; HKDF_SALT_SIZE];
        let routing_keys1 = RoutingKeys::derive(shared_key, &hkdf_salt1);
        let routing_keys2 = RoutingKeys::derive(shared_key, &hkdf_salt2);
        assert_ne!(routing_keys1, routing_keys2);
    }
}
