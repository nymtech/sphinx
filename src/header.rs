use crate::constants::{
    AVERAGE_DELAY, HKDF_INPUT_SEED, MAX_PATH_LENGTH, ROUTING_KEYS_LENGTH, SECURITY_PARAMETER,
    STREAM_CIPHER_KEY_SIZE,
};
use crate::crypto::{generate_random_curve_point, generate_secret, CURVE_GENERATOR};
use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand;
use rand_distr::{Distribution, Exp};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct Address {}

pub enum RouteElement {
    FinalHop(Destination),
    ForwardHop(Host),
}

impl RouteElement {
    fn get_pub_key(&self) -> MontgomeryPoint {
        use RouteElement::*;

        match self {
            FinalHop(destination) => destination.pub_key,
            ForwardHop(host) => host.pub_key,
        }
    }
}

pub struct Destination {
    pub pub_key: MontgomeryPoint,
}

pub struct Host {
    pub address: Address,
    pub pub_key: MontgomeryPoint,
}

struct KeyMaterial {
    initial_shared_secret: SharedSecret,
    shared_keys: Vec<SharedKey>,
}

#[derive(Debug, PartialEq)]
pub struct RoutingKeys {
    stream_cipher_key: [u8; STREAM_CIPHER_KEY_SIZE],
}

pub struct SphinxHeader {}

pub type SharedSecret = MontgomeryPoint;
pub type SharedKey = MontgomeryPoint;

// needs client's secret key, how should we inject this?
// needs to deal with SURBs too at some point
pub fn create_header(route: &[RouteElement]) -> (SphinxHeader, Vec<SharedKey>) {
    let initial_secret = generate_secret();
    let key_material = derive_key_material(route, initial_secret);
    let delays = generate_delays(route.len() - 1); // we don't generate delay for the destination

    // compute filler strings
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, vec![])
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

fn create_zero_bytes(length: usize) -> Vec<u8> {
    vec![0; length]
}

fn generate_pseudorandom_bytes(
    key: &[u8; STREAM_CIPHER_KEY_SIZE],
    iv: &[u8; STREAM_CIPHER_KEY_SIZE],
    length: usize,
) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(&key[..]);
    let cipher_nonce = GenericArray::from_slice(&iv[..]);

    // generate a random string as an output of a PRNG, which we implement using stream cipher AES_CTR
    let mut cipher = Aes128Ctr::new(cipher_key, cipher_nonce);
    let mut data = vec![0u8; length];

    cipher.apply_keystream(&mut data);

    data
}

fn key_derivation_function(shared_key: SharedKey) -> RoutingKeys {
    let hkdf = Hkdf::<Sha256>::new(None, &shared_key.to_bytes());

    let mut output = [0u8; ROUTING_KEYS_LENGTH];
    hkdf.expand(HKDF_INPUT_SEED, &mut output).unwrap();

    let mut stream_cipher_key: [u8; STREAM_CIPHER_KEY_SIZE] = Default::default();
    stream_cipher_key.copy_from_slice(&output[..STREAM_CIPHER_KEY_SIZE]);

    RoutingKeys { stream_cipher_key }
}

// TODO: remember about the destination
fn generate_filler_string(shared_keys: Vec<SharedKey>) -> Vec<u8> {
    let mut filler_string: Vec<u8> = vec![];
    for x in 0..(shared_keys.len()) {
        // take current filler string then concatenate with string of zeroes of size 2*k (k is the security parameter)
        let zero_bytes = create_zero_bytes(SECURITY_PARAMETER * 2);
        filler_string.extend(&zero_bytes);

        // generate a random string as an output of a PRNG, which we implement using stream cipher AES_CTR
        // key for AES_CTR will be shared_keys[x]
        // we also put into AES a nonce as data. this nonce can be for example a sequence of zeros (or some other fixed string)
        // after computing the output vector of AES_CTR we take the last 2*k*x elements of the returned vector
    }

    // start with empty filler string
    // then have the for loop:
    // iterate through all hops:
    // take current filler string then concatenate with string of zeroes of size 2*k (k is the security parameter)
    // then xor the result with output of PRNG seeded with shared key of the iteration
    // take some bits as specified in the paper...
    // this gives new filler string.
    // repeat the loop

    vec![]
}

fn generate_delays(number: usize) -> Vec<f64> {
    let exp = Exp::new(1.0 / AVERAGE_DELAY).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| exp.sample(&mut rand::thread_rng()))
        .collect()
}

fn compute_shared_key(node_pub_key: MontgomeryPoint, exponent: &Scalar) -> SharedKey {
    node_pub_key * exponent
}

fn compute_blinding_factor(shared_key: MontgomeryPoint, exponent: &Scalar) -> Scalar {
    let shared_secret = CURVE_GENERATOR * exponent;
    compute_keyed_hmac(shared_secret.to_bytes(), shared_key.to_bytes())
}

// derive shared keys, group elements, blinding factors
fn derive_key_material(route: &[RouteElement], initial_secret: Scalar) -> KeyMaterial {
    let initial_shared_secret = CURVE_GENERATOR * initial_secret;

    let shared_keys = route
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
        .collect();

    KeyMaterial {
        shared_keys,
        initial_shared_secret,
    }
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
    describe "generating delays" {
        context "for 0 delays" {
            it "returns an empty delays vector" {
                let delays = generate_delays(0);
                assert_eq!(0, delays.len());
    }
        }

        context "for 1 delay" {
            it "returns 1 delay" {
                let delays = generate_delays(1);
                assert_eq!(1, delays.len());
    }
        }

        context "for 3 delays" {
            it "returns 3 delays" {
                let delays = generate_delays(3);
                assert_eq!(3, delays.len());
    }
        }
    }

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
        fn new_route_forward_hop(pub_key: MontgomeryPoint) -> RouteElement {
            RouteElement::ForwardHop(Host {
                address: Address {},
                pub_key,
            })
        }

        fn new_route_final_hop(pub_key: MontgomeryPoint) -> RouteElement {
            RouteElement::FinalHop(Destination {
                pub_key,
            })
        }

        context "with an empty route" {
            before {
                let empty_route: Vec<RouteElement> = vec![];
                let initial_secret = generate_secret();
                let key_material = derive_key_material(&empty_route, initial_secret);
            }

            it "returns no shared keys" {
                assert_eq!(0, key_material.shared_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }
        }

        context "with a route with no forward hops and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_final_hop(generate_random_curve_point())
                ];
        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);
            }

            it "returns number of shared keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.shared_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
    }

            it "generates correct shared keys" {
                // The accumulator is the key to our blinding factors working. If the accumulator value isn't incremented
                // correctly, we risk passing an incorrectly blinded shared key through the mixnet in the (unencrypted)
                // Sphinx packet header. So this test ensures that the accumulator gets incremented properly
                // on each run through the loop.
                let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;

                    assert_eq!(expected_shared_key, key_material.shared_keys[i])
                }
            }
        }

        context "with a route with 1 forward hop and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_final_hop(generate_random_curve_point())
                ];
        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);
            }

            it "returns number of shared keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.shared_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
    }

            it "generates correct shared keys" {
                // The accumulator is the key to our blinding factors working. If the accumulator value isn't incremented
                // correctly, we risk passing an incorrectly blinded shared key through the mixnet in the (unencrypted)
                // Sphinx packet header. So this test ensures that the accumulator gets incremented properly
                // on each run through the loop.
                let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;

                    assert_eq!(expected_shared_key, key_material.shared_keys[i])
                }
            }
        }

        context "with a route with 3 forward hops and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_final_hop(generate_random_curve_point())
                ];
        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);
            }

            it "returns number of shared keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.shared_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }

            it "generates correct shared keys" {
                // The accumulator is the key to our blinding factors working. If the accumulator value isn't incremented
                // correctly, we risk passing an incorrectly blinded shared key through the mixnet in the (unencrypted)
                // Sphinx packet header. So this test ensures that the accumulator gets incremented properly
                // on each run through the loop.
        let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;

                    assert_eq!(expected_shared_key, key_material.shared_keys[i])
                }
            }
        }

        context "with a route with 3 forward hops and no destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point())
                ];
                let initial_secret = generate_secret();
                let key_material = derive_key_material(&route, initial_secret);
            }

            it "returns number of shared keys equal to length of entire route" {
                assert_eq!(route.len(), key_material.shared_keys.len())
            }

            it "returns correctly generated initial shared secret g^x,
                where g is the curve generator and x is initial secret" {
                assert_eq!(CURVE_GENERATOR * initial_secret, key_material.initial_shared_secret)
            }

            it "generates correct shared keys" {
        // The accumulator is the key to our blinding factors working. If the accumulator value isn't incremented
        // correctly, we risk passing an incorrectly blinded shared key through the mixnet in the (unencrypted)
        // Sphinx packet header. So this test ensures that the accumulator gets incremented properly
        // on each run through the loop.
                let mut expected_accumulator = initial_secret;
                for i in 0..route.len() {
                    let expected_shared_key = compute_shared_key(route[i].get_pub_key(), &expected_accumulator);
                    let expected_blinder = compute_blinding_factor(expected_shared_key, &expected_accumulator);
                    expected_accumulator = expected_accumulator * expected_blinder;

                    assert_eq!(expected_shared_key, key_material.shared_keys[i])
                }
            }
    }
    }

    describe "xor" {
        context "for empty inputs" {
            it "returns an empty vector" {
                let a: Vec<u8> = vec![];
                let b: Vec<u8> = vec![];
                let c = xor(&a, &b);
                assert_eq!(0, c.len());
            }
        }

        context "for non-zero inputs of same length" {
            it "returns the expected xor of the vectors" {
                let a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5, 6];
                let c = xor(&a, &b);
                assert_eq!(a.len(), c.len());
                for i in 0..c.len() {
                    assert_eq!(c[i], a[i] ^ b[i])
                }
            }
        }

        context "for inputs of different lengths" {
            #[should_panic]
            it "panics" {
                let a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5];
                let c = xor(&a, &b);
            }
        }
    }

    describe "creating vector of zero bytes" {
        it "creates vector containing only zeroes of given length" {
            let zeroes = create_zero_bytes(42);
            assert_eq!(42, zeroes.len());
            for i in 0..zeroes.len() {
                assert_eq!(0, zeroes[i]);
            }
        }
    }

    describe "generating pseudorandom bytes" {
        it "generates outputs of expected length" {
            let key: [u8; STREAM_CIPHER_KEY_SIZE] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
            let iv: [u8; STREAM_CIPHER_KEY_SIZE] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

            let rand_bytes = generate_pseudorandom_bytes(&key, &iv, 10000);
            assert_eq!(10000, rand_bytes.len());
        }
    }

    describe "key derivation function" {
        it "expands the seed key to expected length" {
            let shared_key = generate_random_curve_point();
            let routing_keys = key_derivation_function(shared_key);
            assert_eq!(STREAM_CIPHER_KEY_SIZE, routing_keys.stream_cipher_key.len());
        }
        it "returns the same output for two equal inputs" {
            let shared_key = generate_random_curve_point();
            let routing_keys1 = key_derivation_function(shared_key);
            let routing_keys2 = key_derivation_function(shared_key);
            assert_eq!(routing_keys1, routing_keys2);
        }
    }
}
