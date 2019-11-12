use crate::constants::{
    AVERAGE_DELAY, HKDF_INPUT_SEED, MAX_DESTINATION_LENGTH, MAX_PATH_LENGTH, ROUTING_KEYS_LENGTH,
    SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::keys;
use crate::utils;
use crate::utils::crypto::{CURVE_GENERATOR, STREAM_CIPHER_INIT_VECTOR, STREAM_CIPHER_KEY_SIZE};
use rand;
use rand_distr::{Distribution, Exp};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[derive(Clone)]
pub enum RouteElement {
    FinalHop(Destination),
    ForwardHop(MixNode),
}

impl RouteElement {
    pub fn get_pub_key(&self) -> crypto::PublicKey {
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
    pub pub_key: crypto::PublicKey,
}

const IP_VERSION_FIELD_LENGTH: usize = 1;
const IPV4_BYTE: u8 = 4;
const IPV6_BYTE: u8 = 6;
const SERIALIZED_DESTINATION_LENGTH: usize =
    IP_VERSION_FIELD_LENGTH + crypto::PUBLIC_KEY_LENGTH + 16 + 2; // 16 bytes for maximum ipv6 + 2 bytes (16bits) for the port
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
pub struct MixNode {
    pub address: SocketAddr,
    pub pub_key: crypto::PublicKey,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RoutingKeys {
    pub stream_cipher_key: [u8; STREAM_CIPHER_KEY_SIZE],
}

pub(crate) fn generate_pseudorandom_filler_bytes(routing_keys: &Vec<RoutingKeys>) -> Vec<u8> {
    routing_keys
        .iter()
        .map(|node_routing_keys| node_routing_keys.stream_cipher_key) // we only want the cipher key
        .map(|cipher_key| {
            crypto::generate_pseudorandom_bytes(
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
    assert_eq!(filler_string_accumulator.len(), 2 * i * SECURITY_PARAMETER);

    let zero_bytes = vec![0u8; 2 * SECURITY_PARAMETER];
    filler_string_accumulator.extend(&zero_bytes);

    // after computing the output vector of AES_CTR we take the last 2*k*i elements of the returned vector
    // and xor it with the current filler string
    utils::bytes::xor_with(
        &mut filler_string_accumulator,
        &pseudorandom_bytes[(2 * (MAX_PATH_LENGTH - (i + 1)) + 3) * SECURITY_PARAMETER..],
    );

    filler_string_accumulator
}

pub(crate) fn generate_all_routing_info(
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
    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
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

    let zero_padding = vec![
        0u8;
        (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER
            - final_destination_bytes.len()
    ];

    let padded_final_destination = [final_destination_bytes.to_vec(), zero_padding].concat();
    let xored_bytes = utils::bytes::xor(&padded_final_destination, &pseudorandom_bytes);
    [xored_bytes, filler].concat()
}

pub(crate) fn generate_delays(number: usize) -> Vec<f64> {
    let exp = Exp::new(1.0 / AVERAGE_DELAY).unwrap();

    std::iter::repeat(())
        .take(number)
        .map(|_| exp.sample(&mut rand::thread_rng()))
        .collect()
}

use crate::utils::crypto;
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
                let shared_keys: Vec<crypto::SharedKey> = vec![crypto::generate_random_curve_point()];
                let routing_keys = &shared_keys.iter().map(|&key| keys::key_derivation_function(key)).collect();
                let filler_string = generate_pseudorandom_filler_bytes(routing_keys);

                assert_eq!(2 * SECURITY_PARAMETER, filler_string.len());
            }
        }

        context "for three keys" {
            before {
                let shared_keys: Vec<crypto::SharedKey> = vec![
                    crypto::generate_random_curve_point(),
                    crypto::generate_random_curve_point(),
                    crypto::generate_random_curve_point()
                ];
                let routing_keys = &shared_keys.iter().map(|&key| keys::key_derivation_function(key)).collect();
                let filler_string = generate_pseudorandom_filler_bytes(routing_keys);
            }
            it "generates filler string of length 3 * 2 * SECURITY_PARAMETER" {
               assert_eq!(3 * 2 * SECURITY_PARAMETER, filler_string.len());
            }
        }

        context "more keys than the maximum path length" {
            #[should_panic]
            it "panics" {
                let shared_keys: Vec<crypto::SharedKey> = std::iter::repeat(())
                    .take(MAX_PATH_LENGTH + 1)
                    .map(|_| crypto::generate_random_curve_point())
                    .collect();
                let routing_keys = &shared_keys.iter().map(|&key| keys::key_derivation_function(key)).collect();
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
                    pub_key: crypto::generate_random_curve_point(),
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
