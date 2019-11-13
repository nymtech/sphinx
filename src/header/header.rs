use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[cfg(test)]
use speculate::speculate;

use crate::constants::{
    AVERAGE_DELAY, HKDF_INPUT_SEED, MAX_DESTINATION_LENGTH, MAX_PATH_LENGTH, ROUTING_KEYS_LENGTH,
    SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::keys;
use crate::utils;
use crate::utils::crypto;
use crate::utils::crypto::{CURVE_GENERATOR, STREAM_CIPHER_INIT_VECTOR, STREAM_CIPHER_KEY_SIZE};

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

pub type AddressBytes = [u8; 32];

#[derive(Clone)]
pub struct Destination {
    pub address: AddressBytes,
    pub pub_key: crypto::PublicKey,
}

#[derive(Clone)]
pub struct MixNode {
    pub address: AddressBytes,
    pub pub_key: crypto::PublicKey,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RoutingKeys {
    pub stream_cipher_key: [u8; STREAM_CIPHER_KEY_SIZE],
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
    let final_destination_bytes = address_fixture();

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

#[cfg(test)]
speculate! {
    describe "encapsulation of the final routing information" {
        context "for IPV4" {
            it "produces result of length filler plus pseudorandom bytes lengths" {
                let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
                let route_len = 4;
                let filler = vec![0u8; 25];
                let destination = Destination {
                    pub_key: crypto::generate_random_curve_point(),
                    address: address_fixture(),
                };
    //                generate_final_routing_info(filler, route_len, destination, pseudorandom_bytes);
                assert_eq!(true, true);
            }
        }
    }
}

pub fn address_fixture() -> AddressBytes {
    [0u8; 32]
}
