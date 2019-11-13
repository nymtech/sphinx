use crate::constants::{HKDF_INPUT_SEED, ROUTING_KEYS_LENGTH};
use crate::header::header::{address_fixture, Destination, MixNode, RouteElement, RoutingKeys};
use crate::utils::crypto;
use crate::utils::crypto::CURVE_GENERATOR;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct KeyMaterial {
    initial_shared_secret: crypto::SharedSecret,
    pub routing_keys: Vec<RoutingKeys>,
}

// derive shared keys, group elements, blinding factors
pub fn derive(route: &[RouteElement], initial_secret: Scalar) -> KeyMaterial {
    let initial_shared_secret = CURVE_GENERATOR * initial_secret;

    let routing_keys = route
        .iter()
        .scan(initial_secret, |accumulator, route_element| {
            let shared_key = compute_shared_key(route_element.get_pub_key(), &accumulator);

            // last element in the route should be the destination and hence don't compute blinding factor
            // or increment the iterator
            match route_element {
                RouteElement::ForwardHop(_) => {
                    *accumulator = *accumulator * compute_blinding_factor(shared_key, &accumulator)
                }
                RouteElement::FinalHop(_) => (),
            }

            Some(shared_key)
        })
        .map(key_derivation_function)
        .collect();

    KeyMaterial {
        routing_keys,
        initial_shared_secret,
    }
}

fn compute_blinding_factor(shared_key: crypto::SharedKey, exponent: &Scalar) -> Scalar {
    let shared_secret = CURVE_GENERATOR * exponent;
    compute_keyed_hmac(shared_secret.to_bytes(), shared_key.to_bytes())
}

// Given that everything here except RoutingKeys lives in the `crypto` module, I think
// that this one could potentially move most of its functionality there quite profitably.
pub(crate) fn key_derivation_function(shared_key: crypto::SharedKey) -> RoutingKeys {
    let hkdf = Hkdf::<Sha256>::new(None, &shared_key.to_bytes());

    let mut output = [0u8; ROUTING_KEYS_LENGTH];
    hkdf.expand(HKDF_INPUT_SEED, &mut output).unwrap();

    let mut stream_cipher_key: [u8; crypto::STREAM_CIPHER_KEY_SIZE] = Default::default();
    stream_cipher_key.copy_from_slice(&output[..crypto::STREAM_CIPHER_KEY_SIZE]);

    RoutingKeys { stream_cipher_key }
}

fn compute_shared_key(node_pub_key: crypto::PublicKey, exponent: &Scalar) -> crypto::SharedKey {
    node_pub_key * exponent
}

fn compute_keyed_hmac(alpha: [u8; 32], data: [u8; 32]) -> Scalar {
    let mut mac = HmacSha256::new_varkey(&alpha).expect("HMAC can take key of any size");
    mac.input(&data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.result().code().to_vec()[..32]);
    Scalar::from_bytes_mod_order(output)
}

#[cfg(test)]
use speculate::speculate;

#[cfg(test)]
speculate! {
    describe "computing shared key" {
        it "returns g^x for predefined g and x, where g is a point on the curve and x is an exponent" {
            let x = Scalar::from_bytes_mod_order([42u8; 32]);
            let g = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);

            let expected_shared_key = g * x;
            let shared_key = compute_shared_key(g, &x);

            assert_eq!(expected_shared_key, shared_key);
        }
    }

    describe "computing blinding factor" {
        it "returns expected H(g^x, y) for predefined x and y, where
            H is an HMAC function,
            g is the curve generator
            x is a scalar
            y is a shared key (g^z), where z is a scalar"
        {
            let x = Scalar::from_bytes_mod_order([42u8; 32]);
            let y = CURVE_GENERATOR * Scalar::from_bytes_mod_order([16u8; 32]);

        // given the above exponent and shared key, we should see:
        let expected_blinding_factor = Scalar::from_bytes_mod_order([
            65, 236, 88, 7, 186, 168, 172, 170, 90, 46, 49, 164, 225, 73, 145, 77, 181, 151, 37,
            178, 37, 181, 248, 165, 180, 75, 103, 133, 191, 146, 10, 8,
        ]);

            let blinding_factor = compute_blinding_factor(y, &x);
            assert_eq!(expected_blinding_factor, blinding_factor)
        }
    }

    // I've included so many contexts as we might change behaviour based on RouteElement being
    // ForwardHop or FinalHop. We want the tests to break in that case.
    describe "deriving key material" {
        fn new_route_forward_hop(pub_key: crypto::PublicKey) -> RouteElement {
            RouteElement::ForwardHop(MixNode {
                address: address_fixture(),
                pub_key,
            })
        }

        fn new_route_final_hop(pub_key: crypto::PublicKey, address: crate::header::header::AddressBytes) -> RouteElement {
            RouteElement::FinalHop(Destination {
                pub_key, address
            })
        }

        context "with an empty route" {
            before {
                let empty_route: Vec<RouteElement> = vec![];
                let initial_secret = crypto::generate_secret();
                let key_material = derive(&empty_route, initial_secret);
            }

            it "returns no routing keys" {
                assert_eq!(0, key_material.routing_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }
        }

        context "with a route with no forward hops and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_final_hop(crypto::generate_random_curve_point(), address_fixture())
                ];
                let initial_secret = crypto::generate_secret();
                let key_material = derive(&route, initial_secret);
            }

            it "returns number of shared keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.routing_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }

            it "generates correct routing keys" {
                // The accumulator is the key to our blinding factors working.
                // If the accumulator value isn't incremented correctly, we risk passing an
                // incorrectly blinded shared key through the mixnet in the (unencrypted)
                // Sphinx packet header. So this test ensures that the accumulator gets incremented
                // properly on each run through the loop.
                let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(
                        route[i].get_pub_key(),
                        &expected_accumulator
                    );
                    let expected_blinder = compute_blinding_factor(
                        expected_shared_key, &expected_accumulator
                    );
                    expected_accumulator = expected_accumulator * expected_blinder;
                    let expected_routing_keys = key_derivation_function(expected_shared_key);

                    assert_eq!(expected_routing_keys, key_material.routing_keys[i])
                }
            }
        }

        context "with a route with 1 forward hop and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(crypto::generate_random_curve_point()),
                    new_route_final_hop(crypto::generate_random_curve_point(), address_fixture())
                ];
                let initial_secret = crypto::generate_secret();
                let key_material = derive(&route, initial_secret);
            }

            it "returns number of routing keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.routing_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }

            it "generates correct routing keys" {
                // The accumulator is the key to our blinding factors working. If the accumulator
                // value isn't incremented correctly, we risk passing an incorrectly blinded
                // shared key through the mixnet in the (unencrypted) Sphinx packet header.
                // So this test ensures that the accumulator gets incremented properly
                // on each run through the loop.
                let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;
                    let expected_routing_keys = key_derivation_function(expected_shared_key);
                    assert_eq!(expected_routing_keys, key_material.routing_keys[i])
                }
            }
        }

        context "with a route with 3 forward hops and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(crypto::generate_random_curve_point()),
                    new_route_forward_hop(crypto::generate_random_curve_point()),
                    new_route_forward_hop(crypto::generate_random_curve_point()),
                    new_route_final_hop(crypto::generate_random_curve_point(), address_fixture())
                ];
                let initial_secret = crypto::generate_secret();
                let key_material = derive(&route, initial_secret);
            }

            it "returns number of routing keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.routing_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }

            it "generates correct routing keys" {
            // The accumulator is the key to our blinding factors working. If the accumulator value isn't incremented
            // correctly, we risk passing an incorrectly blinded shared key through the mixnet in the (unencrypted)
            // Sphinx packet header. So this test ensures that the accumulator gets incremented properly
            // on each run through the loop.
            let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;
                    let expected_routing_keys = key_derivation_function(expected_shared_key);

                    assert_eq!(expected_routing_keys, key_material.routing_keys[i])
                }
            }
        }

        context "with a route with 3 forward hops and no destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(crypto::generate_random_curve_point()),
                    new_route_forward_hop(crypto::generate_random_curve_point()),
                    new_route_forward_hop(crypto::generate_random_curve_point())
                ];
                let initial_secret = crypto::generate_secret();
                let key_material = derive(&route, initial_secret);
            }

            it "returns number of routing keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.routing_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }

            it "generates correct routing keys" {
                // The accumulator is the key to our blinding factors working.
                // If the accumulator value isn't incremented correctly, we risk passing an
                // incorrectly blinded shared key through the mixnet in the (unencrypted)
                // Sphinx packet header. So this test ensures that the accumulator gets incremented
                // properly on each run through the loop.
                let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;
                    let expected_routing_keys = key_derivation_function(expected_shared_key);

                    assert_eq!(expected_routing_keys, key_material.routing_keys[i])
                }
            }
        }
    }

    describe "key derivation function" {
        it "expands the seed key to expected length" {
            let shared_key = crypto::generate_random_curve_point();
            let routing_keys = key_derivation_function(shared_key);
            assert_eq!(crypto::STREAM_CIPHER_KEY_SIZE, routing_keys.stream_cipher_key.len());
        }
        it "returns the same output for two equal inputs" {
            let shared_key = crypto::generate_random_curve_point();
            let routing_keys1 = key_derivation_function(shared_key);
            let routing_keys2 = key_derivation_function(shared_key);
            assert_eq!(routing_keys1, routing_keys2);
        }
    }
}
