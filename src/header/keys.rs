use std::fmt;

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::constants::{
    BLINDING_FACTOR_SIZE, HKDF_INPUT_SEED, INTEGRITY_MAC_KEY_SIZE, PAYLOAD_KEY_SIZE,
    ROUTING_KEYS_LENGTH,
};
use crate::crypto;
use crate::crypto::{compute_keyed_hmac, CURVE_GENERATOR, STREAM_CIPHER_KEY_SIZE};
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
    pub blinding_factor: BlindingFactor,
}

impl RoutingKeys {
    // or should this be renamed to 'new'?
    // Given that everything here except RoutingKeys lives in the `crypto` module, I think
    // that this one could potentially move most of its functionality there quite profitably.
    pub fn derive(shared_key: crypto::SharedKey) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &shared_key.to_bytes());

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
    pub fn derive(route: &[Node], initial_secret: Scalar) -> Self {
        let initial_shared_secret = CURVE_GENERATOR * initial_secret;

        let routing_keys = route
            .iter()
            .scan(initial_secret, |accumulator, node| {
                let shared_key = Self::compute_shared_key(node.pub_key, &accumulator);
                let routing_keys = RoutingKeys::derive(shared_key);

                // TODO: if we're on last iteration, do NOT compute_blinding_factor (no need for it)
                *accumulator *= Scalar::from_bytes_mod_order(routing_keys.blinding_factor);
                Some(routing_keys)
            })
            .collect();

        Self {
            routing_keys,
            initial_shared_secret,
        }
    }

    #[allow(dead_code)]
    fn compute_blinding_factor(shared_key: crypto::SharedKey, exponent: &Scalar) -> Scalar {
        let shared_secret = CURVE_GENERATOR * exponent;
        let hmac_full = compute_keyed_hmac(
            shared_secret.to_bytes().to_vec(),
            &shared_key.to_bytes().to_vec(),
        );
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&hmac_full[..32]);
        Scalar::from_bytes_mod_order(hmac)
    }

    pub fn compute_shared_key(base: crypto::PublicKey, exponent: &Scalar) -> crypto::SharedKey {
        base * exponent
    }
}

#[cfg(test)]
mod computing_shared_key {
    use super::*;

    #[test]
    fn it_returns_g_to_power_x() {
        let g = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);
        let x = Scalar::from_bytes_mod_order([42u8; 32]);

        assert_eq!(g * x, KeyMaterial::compute_shared_key(g, &x));
    }
}

#[cfg(test)]
mod computing_blinding_factor {
    use super::*;

    #[test]
    fn it_returns_hash_of_g_to_the_power_x_with_y() {
        //        returns expected H(g^x, y) for predefined x and y, where
        //            H is an HMAC function,
        //            g is the curve generator
        //            x is a scalar
        //            y is a shared key (g^z), where z is a scalar
        let x = Scalar::from_bytes_mod_order([42u8; 32]);
        let y = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);

        // given the above exponent and shared key, we should see:
        let expected_blinding_factor = Scalar::from_bytes_mod_order([
            65, 236, 88, 7, 186, 168, 172, 170, 90, 46, 49, 164, 225, 73, 145, 77, 181, 151, 37,
            178, 37, 181, 248, 165, 180, 75, 103, 133, 191, 146, 10, 8,
        ]);

        let blinding_factor = KeyMaterial::compute_blinding_factor(y, &x);
        assert_eq!(expected_blinding_factor, blinding_factor)
    }
}

//
#[cfg(test)]
mod deriving_key_material {
    use crate::route::Node;

    use super::*;

    #[cfg(test)]
    mod with_an_empty_route {
        use super::*;

        #[test]
        fn it_returns_no_routing_keys() {
            let empty_route: Vec<Node> = vec![];
            let initial_secret = crypto::generate_secret();
            let key_material = KeyMaterial::derive(&empty_route, initial_secret);
            assert_eq!(0, key_material.routing_keys.len());
            assert_eq!(
                CURVE_GENERATOR * initial_secret,
                key_material.initial_shared_secret
            )
        }
    }

    #[cfg(test)]
    mod for_a_route_with_3_forward_hops {
        use crate::route::random_node;

        use super::*;

        fn setup() -> (Vec<Node>, Scalar, KeyMaterial) {
            let route: Vec<Node> = vec![random_node(), random_node(), random_node()];
            let initial_secret = crypto::generate_secret();
            let key_material = KeyMaterial::derive(&route, initial_secret);
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
                CURVE_GENERATOR * initial_secret,
                key_material.initial_shared_secret
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
            for i in 0..3 {
                let expected_shared_key =
                    KeyMaterial::compute_shared_key(route[i].pub_key, &expected_accumulator);
                let expected_routing_keys = RoutingKeys::derive(expected_shared_key);
                expected_accumulator *=
                    Scalar::from_bytes_mod_order(expected_routing_keys.blinding_factor);
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
        let shared_key = crypto::generate_random_curve_point();
        let routing_keys = RoutingKeys::derive(shared_key);
        assert_eq!(
            crypto::STREAM_CIPHER_KEY_SIZE,
            routing_keys.stream_cipher_key.len()
        );
    }

    #[test]
    fn it_returns_the_same_output_for_two_equal_inputs() {
        let shared_key = crypto::generate_random_curve_point();
        let routing_keys1 = RoutingKeys::derive(shared_key);
        let routing_keys2 = RoutingKeys::derive(shared_key);
        assert_eq!(routing_keys1, routing_keys2);
    }
}

#[allow(dead_code)]
pub fn routing_keys_fixture() -> RoutingKeys {
    RoutingKeys {
        stream_cipher_key: [1u8; crypto::STREAM_CIPHER_KEY_SIZE],
        header_integrity_hmac_key: [2u8; INTEGRITY_MAC_KEY_SIZE],
        payload_key: [3u8; PAYLOAD_KEY_SIZE],
        blinding_factor: [4u8; BLINDING_FACTOR_SIZE],
    }
}
