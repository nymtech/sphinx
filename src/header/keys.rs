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
    BLINDING_FACTOR_SIZE, HKDF_INPUT_SEED, INTEGRITY_MAC_KEY_SIZE, PAYLOAD_KEY_SIZE,
    ROUTING_KEYS_LENGTH,
};
use crate::crypto;
use crate::crypto::STREAM_CIPHER_KEY_SIZE;
use crate::route::Node;
use curve25519_dalek::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;
use std::convert::TryInto;
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};

pub type StreamCipherKey = [u8; STREAM_CIPHER_KEY_SIZE];
pub type HeaderIntegrityMacKey = [u8; INTEGRITY_MAC_KEY_SIZE];
// TODO: perhaps change PayloadKey to a Vec considering it's almost 200 bytes long?
// we will lose length assertions but won't need to copy all that data every single function call
pub type PayloadKey = [u8; PAYLOAD_KEY_SIZE];

#[derive(Clone)]
pub struct RoutingKeys {
    pub stream_cipher_key: StreamCipherKey,
    pub header_integrity_hmac_key: HeaderIntegrityMacKey,
    pub payload_key: PayloadKey,
    pub blinding_factor: StaticSecret,
}

impl RoutingKeys {
    // or should this be renamed to 'new'?
    // Given that everything here except RoutingKeys lives in the `crypto` module, I think
    // that this one could potentially move most of its functionality there quite profitably.
    pub fn derive(shared_key: PublicKey) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, shared_key.as_bytes());

        let mut i = 0;
        let mut output = [0u8; ROUTING_KEYS_LENGTH];
        // SAFETY: the length of the provided okm is within the allowed range
        #[allow(clippy::unwrap_used)]
        hkdf.expand(HKDF_INPUT_SEED, &mut output).unwrap();

        let mut stream_cipher_key: [u8; crypto::STREAM_CIPHER_KEY_SIZE] = Default::default();
        stream_cipher_key.copy_from_slice(&output[i..i + crypto::STREAM_CIPHER_KEY_SIZE]);
        i += crypto::STREAM_CIPHER_KEY_SIZE;

        let mut header_integrity_hmac_key: [u8; INTEGRITY_MAC_KEY_SIZE] = Default::default();
        header_integrity_hmac_key.copy_from_slice(&output[i..i + INTEGRITY_MAC_KEY_SIZE]);
        i += INTEGRITY_MAC_KEY_SIZE;

        let mut payload_key: [u8; PAYLOAD_KEY_SIZE] = [0u8; PAYLOAD_KEY_SIZE];
        payload_key.copy_from_slice(&output[i..i + PAYLOAD_KEY_SIZE]);
        i += PAYLOAD_KEY_SIZE;

        //Safety, converting a slice of size BLINDING_FACTOR_SIZE into an array of type [u8; BLINDING_FACTOR_SIZE], hence unwrap is fine
        #[allow(clippy::unwrap_used)]
        let blinding_factor_bytes: [u8; BLINDING_FACTOR_SIZE] =
            output[i..i + BLINDING_FACTOR_SIZE].try_into().unwrap();
        let blinding_factor = StaticSecret::from(blinding_factor_bytes);

        Self {
            stream_cipher_key,
            header_integrity_hmac_key,
            payload_key,
            blinding_factor,
        }
    }
}

impl fmt::Debug for RoutingKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RoutingKeys")
            .field("stream_cipher_key", &self.stream_cipher_key)
            .field("header_integrity_hmac_key", &self.header_integrity_hmac_key)
            .field("payload_key", &self.payload_key)
            .field("blinding_factor", self.blinding_factor.as_bytes())
            .finish()
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
    pub initial_shared_secret: PublicKey,
    // why this is here?
    pub routing_keys: Vec<RoutingKeys>,
}

impl KeyMaterial {
    // derive shared keys, group elements, blinding factors
    pub fn derive(route: &[Node], initial_secret: &StaticSecret) -> Self {
        let initial_shared_secret = PublicKey::from(initial_secret);
        let mut routing_keys = Vec::with_capacity(route.len());

        let mut blinding_factors = vec![initial_secret.clone()];
        for (i, node) in route.iter().enumerate() {
            let shared_key = blinding_factors
                .iter()
                .fold(node.pub_key, |acc, blinding_factor| {
                    PublicKey::from(blinding_factor.diffie_hellman(&acc).to_bytes())
                });
            let node_routing_keys = RoutingKeys::derive(shared_key);

            // it's not the last iteration
            if i != route.len() + 1 {
                blinding_factors.push(node_routing_keys.blinding_factor.clone());
            }

            routing_keys.push(node_routing_keys);
        }

        Self {
            initial_shared_secret,
            routing_keys,
        }
    }

    #[deprecated]
    pub fn derive_legacy(route: &[Node], initial_secret: &StaticSecret) -> Self {
        let initial_secret_scalar = Scalar::from_bytes_mod_order(initial_secret.to_bytes());

        let initial_shared_secret =
            curve25519_dalek::MontgomeryPoint::mul_base(&initial_secret_scalar);

        let mut routing_keys = Vec::with_capacity(route.len());

        let mut accumulator = initial_secret_scalar;
        for (i, node) in route.iter().enumerate() {
            // pub^{a * b * ...}
            let pk_mt = curve25519_dalek::MontgomeryPoint(node.pub_key.to_bytes());
            let shared_key = pk_mt * accumulator;

            let node_routing_keys = RoutingKeys::derive(PublicKey::from(shared_key.to_bytes()));

            // it's not the last iteration
            if i != route.len() + 1 {
                // convert the blinding factor to a raw scalar and perform multiplication without
                // any reduction (UNSAFE since we're not in ristretto)
                let blinding_factor_scalar =
                    &Scalar::from_bytes_mod_order(node_routing_keys.blinding_factor.to_bytes());

                accumulator *= blinding_factor_scalar;
            }

            routing_keys.push(node_routing_keys);
        }
        Self {
            initial_shared_secret: PublicKey::from(initial_shared_secret.0),
            routing_keys,
        }
    }
}

#[cfg(test)]
mod deriving_key_material {
    use super::*;
    use crate::route::Node;

    #[cfg(test)]
    mod with_an_empty_route {
        use super::*;

        #[test]
        fn it_returns_no_routing_keys() {
            let empty_route: Vec<Node> = vec![];
            let initial_secret = StaticSecret::random();
            let key_material = KeyMaterial::derive(&empty_route, &initial_secret);
            assert_eq!(0, key_material.routing_keys.len());
            assert_eq!(
                PublicKey::from(&initial_secret).as_bytes(),
                key_material.initial_shared_secret.as_bytes()
            )
        }
    }

    #[cfg(test)]
    mod for_a_route_with_3_forward_hops {
        use super::*;
        use crate::test_utils::random_node;

        fn setup() -> (Vec<Node>, StaticSecret, KeyMaterial) {
            let route: Vec<Node> = vec![random_node(), random_node(), random_node()];
            let initial_secret = StaticSecret::random();
            let key_material = KeyMaterial::derive(&route, &initial_secret);
            (route, initial_secret, key_material)
        }

        #[test]
        fn it_returns_number_of_shared_keys_equal_to_length_of_the_route() {
            let (_, _, key_material) = setup();
            assert_eq!(3, key_material.routing_keys.len());
        }

        #[test]
        fn it_returns_correctly_inited_shared_secret() {
            let (_, initial_secret, key_material) = setup();
            assert_eq!(
                PublicKey::from(&initial_secret).as_bytes(),
                key_material.initial_shared_secret.as_bytes()
            );
        }

        #[test]
        fn it_generates_correct_routing_keys() {
            let (route, initial_secret, key_material) = setup();
            // The accumulator is the key to our blinding factors working.
            // If the accumulator value isn't incremented correctly, we risk passing an
            // incorrectly blinded shared key through the mixnet in the (unencrypted)
            // Sphinx packet header. So this test ensures that the accumulator gets incremented
            // properly on each run through the loop.
            let mut expected_accumulator = vec![initial_secret];
            for (i, node) in route.iter().enumerate() {
                let expected_shared_key =
                    expected_accumulator
                        .iter()
                        .fold(node.pub_key, |acc, blinding_factor| {
                            PublicKey::from(blinding_factor.diffie_hellman(&acc).to_bytes())
                        });

                let expected_routing_keys = RoutingKeys::derive(expected_shared_key);

                expected_accumulator.push(expected_routing_keys.blinding_factor);
                let expected_routing_keys = RoutingKeys::derive(expected_shared_key);
                assert_eq!(expected_routing_keys, key_material.routing_keys[i])
            }
        }
    }
}

#[cfg(test)]
mod key_derivation_function {
    use super::*;

    #[test]
    fn it_expands_the_seed_key_to_expected_length() {
        let initial_secret = StaticSecret::random();
        let shared_key = PublicKey::from(&initial_secret);
        let routing_keys = RoutingKeys::derive(shared_key);
        assert_eq!(
            crypto::STREAM_CIPHER_KEY_SIZE,
            routing_keys.stream_cipher_key.len()
        );
    }

    #[test]
    fn it_returns_the_same_output_for_two_equal_inputs() {
        let initial_secret = StaticSecret::random();
        let shared_key = PublicKey::from(&initial_secret);
        let routing_keys1 = RoutingKeys::derive(shared_key);
        let routing_keys2 = RoutingKeys::derive(shared_key);
        assert_eq!(routing_keys1, routing_keys2);
    }
}
