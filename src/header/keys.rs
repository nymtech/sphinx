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

use crate::constants::{
    BLINDING_FACTOR_SIZE, HKDF_INPUT_SEED, INTEGRITY_MAC_KEY_SIZE, PAYLOAD_KEY_SIZE,
    ROUTING_KEYS_LENGTH,
};
use crate::crypto::STREAM_CIPHER_KEY_SIZE;
use crate::crypto::{self, EphemeralSecret};
use crate::route::Node;
use crypto::SharedSecret;
use curve25519_dalek_ng::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;

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
    pub blinding_factor: BlindingFactor,
}

impl RoutingKeys {
    // or should this be renamed to 'new'?
    // Given that everything here except RoutingKeys lives in the `crypto` module, I think
    // that this one could potentially move most of its functionality there quite profitably.
    pub fn derive(shared_key: crypto::SharedSecret) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, shared_key.as_bytes());

        let mut i = 0;
        let mut output = [0u8; ROUTING_KEYS_LENGTH];
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

        // TODO: we later treat blinding factor as a Scalar, the question is, should it be clamped
        // and/or go through montgomery reduction? We kinda need somebody with good ECC knowledge
        // to answer this question (and other related ones).
        let mut blinding_factor: [u8; BLINDING_FACTOR_SIZE] = Default::default();
        blinding_factor.copy_from_slice(&output[i..i + BLINDING_FACTOR_SIZE]);

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
    pub initial_shared_secret: crypto::SharedSecret,
    // why this is here?
    pub routing_keys: Vec<RoutingKeys>,
}

impl KeyMaterial {
    // derive shared keys, group elements, blinding factors
    pub fn derive(route: &[Node], initial_secret: &EphemeralSecret) -> Self {
        let initial_shared_secret = SharedSecret::from(initial_secret);
        let mut routing_keys = Vec::with_capacity(route.len());

        let mut accumulator = initial_secret.clone();
        for (i, node) in route.iter().enumerate() {
            // pub^{a * b * ...}
            let shared_key = accumulator.diffie_hellman(&node.pub_key);
            // let shared_key = Self::compute_shared_key(node.pub_key, &accumulator);
            let node_routing_keys = RoutingKeys::derive(shared_key);

            // it's not the last iteration
            if i != route.len() + 1 {
                // TODO: do we need to make the reduction here or could we get away with clamping or even nothing at all?
                // considering (I *think*) proper reductions will happen during scalar multiplication, i.e. g^x?
                // So far it *seems* to produce correct result, but could it be the case it introduces
                // some vulnerabilities? Need some ECC expert here.

                // performs montgomery reduction
                let blinding_factor_scalar =
                    &Scalar::from_bytes_mod_order(node_routing_keys.blinding_factor);
                // alternatives:

                // 'only' clamps the scalar
                // let blinding_factor_scalar = crypto::clamp_scalar_bytes(node_routing_keys.blinding_factor);

                // 'only' makes it 255 bit long
                // let blinding_factor_scalar = Scalar::from_bits(node_routing_keys.blinding_factor);
                accumulator *= blinding_factor_scalar;
            }

            routing_keys.push(node_routing_keys);
        }

        Self {
            initial_shared_secret,
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
            let initial_secret = EphemeralSecret::new();
            let hacky_secret_copy = EphemeralSecret::from(initial_secret.to_bytes());
            let key_material = KeyMaterial::derive(&empty_route, &initial_secret);
            assert_eq!(0, key_material.routing_keys.len());
            assert_eq!(
                SharedSecret::from(&hacky_secret_copy).as_bytes(),
                key_material.initial_shared_secret.as_bytes()
            )
        }
    }

    #[cfg(test)]
    mod for_a_route_with_3_forward_hops {
        use super::*;
        use crate::test_utils::random_node;

        fn setup() -> (Vec<Node>, EphemeralSecret, KeyMaterial) {
            let route: Vec<Node> = vec![random_node(), random_node(), random_node()];
            let initial_secret = EphemeralSecret::new();
            let hacky_secret_copy = EphemeralSecret::from(initial_secret.to_bytes());
            let key_material = KeyMaterial::derive(&route, &initial_secret);
            (route, hacky_secret_copy, key_material)
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
                SharedSecret::from(&initial_secret).as_bytes(),
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
            let mut expected_accumulator = initial_secret;
            for (i, node) in route.iter().enumerate() {
                let expected_shared_key = expected_accumulator.diffie_hellman(&node.pub_key);
                let expected_routing_keys = RoutingKeys::derive(expected_shared_key);

                expected_accumulator = &expected_accumulator
                    * &Scalar::from_bytes_mod_order(expected_routing_keys.blinding_factor);
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
        let initial_secret = EphemeralSecret::new();
        let shared_key = SharedSecret::from(&initial_secret);
        let routing_keys = RoutingKeys::derive(shared_key);
        assert_eq!(
            crypto::STREAM_CIPHER_KEY_SIZE,
            routing_keys.stream_cipher_key.len()
        );
    }

    #[test]
    fn it_returns_the_same_output_for_two_equal_inputs() {
        let initial_secret = EphemeralSecret::new();
        let shared_key = SharedSecret::from(&initial_secret);
        let routing_keys1 = RoutingKeys::derive(shared_key);
        let routing_keys2 = RoutingKeys::derive(shared_key);
        assert_eq!(routing_keys1, routing_keys2);
    }
}
