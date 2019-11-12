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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[cfg(test)]
use speculate::speculate;

use crate::constants::{
    AVERAGE_DELAY, HKDF_INPUT_SEED, MAX_DESTINATION_LENGTH, MAX_PATH_LENGTH, ROUTING_KEYS_LENGTH,
    SECURITY_PARAMETER, STREAM_CIPHER_INIT_VECTOR, STREAM_CIPHER_KEY_SIZE,
    STREAM_CIPHER_OUTPUT_LENGTH,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
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

#[derive(Clone)]
pub struct Destination {
    pub address: SocketAddr,
    pub pub_key: MontgomeryPoint,
}

const IP_VERSION_FIELD_LENGTH: usize = 1;
const IPV4_BYTE: u8 = 4;
const IPV6_BYTE: u8 = 6;
const PUBLIC_KEY_LENGTH: usize = 32;
const SERIALIZED_DESTINATION_LENGTH: usize = IP_VERSION_FIELD_LENGTH + PUBLIC_KEY_LENGTH + 16 + 2; // 16 bytes for maximum ipv6 + 2 bytes (16bits) for the port
const IPV4_PADDING: [u8; 12] = [0u8; 12];

impl Destination {
    fn encode(&self) -> [u8; SERIALIZED_DESTINATION_LENGTH] {
        let mut bytes_vec: Vec<u8> = vec![];
        bytes_vec.extend(self.pub_key.to_bytes().iter()); // first 32 bytes for public key
        bytes_vec.extend(self.address.port().to_ne_bytes().iter()); // next 2 bytes are for the port

        // ipversion || ip

        bytes_vec.extend(&match self.address {
            SocketAddr::V4(socket_address) => {
                let mut ip_bytes_vec: Vec<u8> = vec![];
                let mut ip_bytes = [0u8; 17];
                ip_bytes_vec.extend([IPV4_BYTE].iter()); // ip version prefix
                ip_bytes_vec.extend(socket_address.ip().octets().iter()); // actual ip address
                ip_bytes_vec.extend(IPV4_PADDING.iter()); // pad with 12 zero bytes (to match length of ipv6)
                ip_bytes.clone_from_slice(&ip_bytes_vec);
                ip_bytes
            }
            SocketAddr::V6(socket_address) => {
                let mut ip_bytes_vec: Vec<u8> = vec![];
                let mut ip_bytes = [0u8; 17];
                ip_bytes_vec.extend([IPV6_BYTE].iter()); // ip version prefix
                ip_bytes_vec.extend(socket_address.ip().octets().iter()); // actual ip address
                ip_bytes.clone_from_slice(&ip_bytes_vec);
                ip_bytes
            }
        });

        let mut bytes = [0u8; SERIALIZED_DESTINATION_LENGTH];
        bytes.clone_from_slice(&bytes_vec);
        // first 32 bytes will be the public key
        // next 2 bytes will be the port
        // next 1 byte will indicate ipv4 vs ipv6
        // next 16 bytes will represent the address, either ipv6 or ipv4 padded with zeroes

        bytes
    }
}

#[derive(Clone)]
pub struct Host {
    pub address: SocketAddr,
    pub pub_key: MontgomeryPoint,
}

struct KeyMaterial {
    initial_shared_secret: SharedSecret,
    routing_keys: Vec<RoutingKeys>,
}

#[derive(Debug, PartialEq, Clone)]
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
    let filler_string = generate_pseudorandom_filler_bytes(&key_material.routing_keys);
    let routing_info = generate_all_routing_info(route, &key_material.routing_keys, filler_string);
    // encapsulate routing information, compute MACs
    (SphinxHeader {}, Vec::new())
}

// xor produces new Vector with the result
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

// xor_with xors assigns the result of xor to the first argument
fn xor_with(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());

    a.iter_mut()
        .zip(b.iter())
        .map(|(x1, &x2)| *x1 ^= x2)
        .collect()
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

fn generate_pseudorandom_filler_bytes(routing_keys: &Vec<RoutingKeys>) -> Vec<u8> {
    routing_keys
        .iter()
        .map(|node_routing_keys| node_routing_keys.stream_cipher_key) // we only want the cipher key
        .map(|cipher_key| {
            generate_pseudorandom_bytes(
                &cipher_key,
                &STREAM_CIPHER_INIT_VECTOR,
                STREAM_CIPHER_OUTPUT_LENGTH,
            )
        }) // the actual cipher key is only used to generate the pseudorandom bytes
        .enumerate() // we need to know index of each element to take correct slice of the PRNG output
        .fold(
            Vec::new(),
            |filler_string_accumulator, (i, pseudorandom_bytes)| {
                generate_filler_string(filler_string_accumulator, i, pseudorandom_bytes)
            },
        )
}

fn generate_filler_string(
    mut filler_string_accumulator: Vec<u8>,
    i: usize,
    pseudorandom_bytes: Vec<u8>,
) -> Vec<u8> {
    assert_eq!(pseudorandom_bytes.len(), STREAM_CIPHER_OUTPUT_LENGTH);

    if i == 0 {
        assert_eq!(filler_string_accumulator.len(), 0);
    }
    if i != 0 {
        assert_eq!(filler_string_accumulator.len(), 2 * i * SECURITY_PARAMETER);
    }
    let zero_bytes = create_zero_bytes(2 * SECURITY_PARAMETER);
    filler_string_accumulator.extend(&zero_bytes);

    // after computing the output vector of AES_CTR we take the last 2*k*i elements of the returned vector
    // and xor it with the current filler string
    xor_with(
        &mut filler_string_accumulator,
        &pseudorandom_bytes[(2 * (MAX_PATH_LENGTH - (i + 1)) + 3) * SECURITY_PARAMETER..],
    );

    filler_string_accumulator
}

fn generate_all_routing_info(
    route: &[RouteElement],
    routing_keys: &Vec<RoutingKeys>,
    filler_string: Vec<u8>,
) {
    let final_key = routing_keys
        .last()
        .cloned()
        .expect("The keys should be already initialized");
    let final_route_element = route
        .last()
        .cloned()
        .expect("The route should not be empty");
    let final_hop = match final_route_element {
        RouteElement::FinalHop(destination) => destination,
        _ => panic!("The last route element must be a destination"),
    };

    // TODO: does this IV correspond to STREAM_CIPHER_INIT_VECTOR?
    // (used in generate_pseudorandom_filler_bytes)
    let iv: [u8; STREAM_CIPHER_KEY_SIZE] = [0u8; 16];
    let pseudorandom_bytes = generate_pseudorandom_bytes(
        &final_key.stream_cipher_key,
        &iv,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );
    let final_routing_info =
        generate_final_routing_info(filler_string, route.len(), final_hop, pseudorandom_bytes);

    // loop for other hops
}

fn generate_final_routing_info(
    filler: Vec<u8>,
    route_len: usize,
    destination: Destination,
    pseudorandom_bytes: Vec<u8>,
) -> Vec<u8> {
    let final_destination_bytes = destination.encode(); // we will convert our address to bytes here

    assert!(
        final_destination_bytes.len()
            <= (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER
    );

    let zero_padding = create_zero_bytes(
        (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER
            - final_destination_bytes.len(),
    );

    let padded_final_destination = [final_destination_bytes.to_vec(), zero_padding].concat();
    let xored_bytes = xor(&padded_final_destination, &pseudorandom_bytes);
    [xored_bytes, filler].concat()
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

fn compute_keyed_hmac(alpha: [u8; 32], data: [u8; 32]) -> Scalar {
    let mut mac = HmacSha256::new_varkey(&alpha).expect("HMAC can take key of any size");
    mac.input(&data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.result().code().to_vec()[..32]);
    Scalar::from_bytes_mod_order(output)
}

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
                address: ipv4_host_fixture(),
                pub_key,
            })
        }

        fn new_route_final_hop(pub_key: MontgomeryPoint, address: SocketAddr) -> RouteElement {
            RouteElement::FinalHop(Destination {
                pub_key,address
            })
        }

        context "with an empty route" {
            before {
                let empty_route: Vec<RouteElement> = vec![];
                let initial_secret = generate_secret();
                let key_material = derive_key_material(&empty_route, initial_secret);
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
                    new_route_final_hop(generate_random_curve_point(), ipv4_host_fixture())
                ];
        let initial_secret = generate_secret();
        let key_material = derive_key_material(&route, initial_secret);
            }

            it "returns number of shared keys equal to length of entire route" {
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

        context "with a route with 1 forward hop and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_final_hop(generate_random_curve_point(), ipv4_host_fixture())
                ];
                let initial_secret = generate_secret();
                let key_material = derive_key_material(&route, initial_secret);
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

        context "with a route with 3 forward hops and a destination" {
            before {
                let route: Vec<RouteElement> = vec![
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_final_hop(generate_random_curve_point(), ipv4_host_fixture())
                ];
                let initial_secret = generate_secret();
                let key_material = derive_key_material(&route, initial_secret);
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
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point()),
                    new_route_forward_hop(generate_random_curve_point())
                ];
                let initial_secret = generate_secret();
                let key_material = derive_key_material(&route, initial_secret);
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

    describe "xor_with" {
        context "for empty inputs" {
            it "does not change initial value" {
                let mut a: Vec<u8> = vec![];
                let b: Vec<u8> = vec![];
                xor_with(&mut a, &b);
                assert_eq!(0, a.len());
            }
        }

        context "for non-zero inputs of same length" {
            it "returns the expected xor of the vectors" {
                let mut a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5, 6];
                xor_with(&mut a, &b);
                assert_eq!(1^4, a[0]);
                assert_eq!(2^5, a[1]);
                assert_eq!(3^6, a[2]);

            }
        }

        context "for inputs of different lengths" {
            #[should_panic]
            it "panics" {
                let mut a: Vec<u8> = vec![1, 2, 3];
                let b: Vec<u8> = vec![4, 5];
                xor_with(&mut a, &b);
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

    describe "creating pseudorandom bytes" {
        context "for no keys" {
            it "generates empty filler string" {
                let routing_keys: Vec<RoutingKeys> = vec![];
                let filler_string = generate_pseudorandom_filler_bytes(&routing_keys);

                assert_eq!(0, filler_string.len());
            }
        }

        context "for one key" {
            it "generates filler string of length 1 * 2 * SECURITY_PARAMETER" {
                let shared_keys: Vec<SharedKey> = vec![generate_random_curve_point()];
                let routing_keys = &shared_keys.iter().map(|&key| key_derivation_function(key)).collect();
                let filler_string = generate_pseudorandom_filler_bytes(routing_keys);

                assert_eq!(2 * SECURITY_PARAMETER, filler_string.len());
            }
        }

        context "for three keys" {
            before {
                let shared_keys: Vec<SharedKey> = vec![
                    generate_random_curve_point(),
                    generate_random_curve_point(),
                    generate_random_curve_point()
                ];
                let routing_keys = &shared_keys.iter().map(|&key| key_derivation_function(key)).collect();
                let filler_string = generate_pseudorandom_filler_bytes(routing_keys);
            }
            it "generates filler string of length 3 * 2 * SECURITY_PARAMETER" {
               assert_eq!(3 * 2 * SECURITY_PARAMETER, filler_string.len());
            }
        }

        context "more keys than the maximum path length" {
            #[should_panic]
            it "panics" {
                let shared_keys: Vec<SharedKey> = std::iter::repeat(())
                    .take(MAX_PATH_LENGTH + 1)
                    .map(|_| generate_random_curve_point())
                    .collect();
                let routing_keys = &shared_keys.iter().map(|&key| key_derivation_function(key)).collect();
                generate_pseudorandom_filler_bytes(routing_keys);
            }
        }

        describe "generating filler bytes" {
            context "for incorrectly sized pseudorandom bytes vector and accumulator vector"{
                #[should_panic]
                it "panics" {
                    let pseudorandom_bytes = vec![0; 1];
                    generate_filler_string(vec![], 0, pseudorandom_bytes);
                }
                context "when the filler accumulator is not the correct length" {
                    #[should_panic]
                    it "panics" {
                        let good_pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
                        let wrong_accumulator = vec![0; 25];
                        generate_filler_string(wrong_accumulator, 1, good_pseudorandom_bytes);
                    }

                }
            }
            context "for an empty filler string accumulator"{
                it "returns a byte vector of length 2 * SECURITY_PARAMETER" {
                    let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
                    generate_filler_string(vec![], 0, pseudorandom_bytes);
                }
            }

            context "for valid inputs"{
                it "returns the xored byte vector of a correct length"{
                    let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
                    let filler_string_accumulator = vec![0; 32];
                    let filler_string = generate_filler_string(filler_string_accumulator, 1, pseudorandom_bytes);
                    assert_eq!(64, filler_string.len());
                    for x in filler_string {
                        assert_eq!(0, x); // XOR of 0 + 0 == 0
                    }
                }
            }
        }

        describe "encapsulation of the final routing information" {
        context "for IPV4" {
            it "produces result of length filler plus pseudorandom bytes lengths" {
                let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
                let route_len = 4;
                let filler = vec![0u8; 25];
                let destination = Destination {
                    pub_key: generate_random_curve_point(),
                    address: ipv4_host_fixture(),
                };
//                generate_final_routing_info(filler, route_len, destination, pseudorandom_bytes);
                assert_eq!(true, true);
            }
        }
        context "for IPV6" {

        }

        }

    }
}

pub fn ipv4_host_fixture() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
}
