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

use crate::constants::INTEGRITY_MAC_KEY_SIZE;
use crate::crypto::STREAM_CIPHER_KEY_SIZE;
use crate::header::shared_secret::{expand_shared_secret, ExpandedSharedSecret};
use crate::route::Node;
use curve25519_dalek::Scalar;
use x25519_dalek::{PublicKey, StaticSecret};

pub type StreamCipherKey = [u8; STREAM_CIPHER_KEY_SIZE];
pub type HeaderIntegrityMacKey = [u8; INTEGRITY_MAC_KEY_SIZE];

pub struct KeyMaterial {
    pub initial_shared_secret: PublicKey,
    pub expanded_shared_secrets: Vec<ExpandedSharedSecret>,
}

impl KeyMaterial {
    // derive shared keys, group elements, blinding factors
    pub fn derive(route: &[Node], initial_secret: &StaticSecret) -> Self {
        let initial_shared_secret = PublicKey::from(initial_secret);
        let mut expanded_shared_secrets = Vec::with_capacity(route.len());

        let mut blinding_factors = vec![initial_secret.clone()];
        for (i, node) in route.iter().enumerate() {
            let shared_key = blinding_factors
                .iter()
                .fold(node.pub_key, |acc, blinding_factor| {
                    // a nasty hack to convert `SharedSecret` into `PublicKey`,
                    // so that we could call `diffie_hellman` repeatedly
                    PublicKey::from(blinding_factor.diffie_hellman(&acc).to_bytes())
                });
            let expanded_shared_secret = expand_shared_secret(shared_key.as_bytes());

            // it's not the last iteration
            if i != route.len() + 1 {
                blinding_factors.push(expanded_shared_secret.blinding_factor());
            }

            expanded_shared_secrets.push(expanded_shared_secret);
        }

        Self {
            initial_shared_secret,
            expanded_shared_secrets,
        }
    }

    #[deprecated]
    pub fn derive_legacy(route: &[Node], initial_secret: &StaticSecret) -> Self {
        let initial_secret_scalar = Scalar::from_bytes_mod_order(initial_secret.to_bytes());

        let initial_shared_secret =
            curve25519_dalek::MontgomeryPoint::mul_base(&initial_secret_scalar);

        let mut expanded_shared_secrets = Vec::with_capacity(route.len());

        let mut accumulator = initial_secret_scalar;
        for (i, node) in route.iter().enumerate() {
            // pub^{a * b * ...}
            let pk_mt = curve25519_dalek::MontgomeryPoint(node.pub_key.to_bytes());
            let shared_key = pk_mt * accumulator;

            let expanded_shared_secret = expand_shared_secret(shared_key.as_bytes());

            // it's not the last iteration
            if i != route.len() + 1 {
                // convert the blinding factor to a raw scalar and perform multiplication without
                // any reduction (UNSAFE since we're not in ristretto)
                let blinding_factor_scalar =
                    &Scalar::from_bytes_mod_order(*expanded_shared_secret.blinding_factor_bytes());

                accumulator *= blinding_factor_scalar;
            }

            expanded_shared_secrets.push(expanded_shared_secret);
        }
        Self {
            initial_shared_secret: PublicKey::from(initial_shared_secret.0),
            expanded_shared_secrets,
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
            assert_eq!(0, key_material.expanded_shared_secrets.len());
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
            assert_eq!(3, key_material.expanded_shared_secrets.len());
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
        fn it_generates_correct_expanded_shared_secret() {
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

                let expected_expanded_ss = expand_shared_secret(expected_shared_key.as_bytes());

                expected_accumulator.push(expected_expanded_ss.blinding_factor());
                assert_eq!(
                    expected_expanded_ss,
                    key_material.expanded_shared_secrets[i]
                )
            }
        }
    }
}
