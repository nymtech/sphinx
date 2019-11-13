#[cfg(test)]
use speculate::speculate;

use crate::constants::{
    AVERAGE_DELAY, DESTINATION_LENGTH, HKDF_INPUT_SEED, IDENTIFIER_LENGTH, INTEGRITY_MAC_KEY_SIZE,
    INTEGRITY_MAC_SIZE, MAX_PATH_LENGTH, ROUTING_KEYS_LENGTH, SECURITY_PARAMETER,
    STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::keys;
use crate::utils;
use crate::utils::bytes;
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

pub type AddressBytes = [u8; DESTINATION_LENGTH];
pub type SURBIdentifier = [u8; SECURITY_PARAMETER];

#[derive(Clone)]
pub struct Destination {
    pub address: AddressBytes,
    pub identifier: SURBIdentifier,
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
    pub header_integrity_hmac_key: [u8; INTEGRITY_MAC_KEY_SIZE],
}

pub struct RoutingInfo {
    pub enc_header: Vec<u8>,
    pub header_integrity_hmac: Vec<u8>,
}

pub(crate) fn generate_all_routing_info(
    route: &[RouteElement],
    routing_keys: &Vec<RoutingKeys>,
    filler_string: Vec<u8>,
) -> RoutingInfo {
    let final_keys = routing_keys
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
    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
        &final_keys.stream_cipher_key,
        &STREAM_CIPHER_INIT_VECTOR,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );
    let final_routing_info =
        generate_final_routing_info(filler_string, route.len(), &final_hop, pseudorandom_bytes);

    // loop for other hops
    let mut routing_info = final_routing_info;
    for i in (0..route.len() - 1).rev() {
        let mut routing_info_mac = crypto::compute_keyed_hmac(
            routing_keys[i + 1].header_integrity_hmac_key.to_vec(),
            &routing_info,
        );
        routing_info_mac.truncate(INTEGRITY_MAC_SIZE);

        let next_node_hop_address = match &route[i] {
            RouteElement::ForwardHop(mixnode) => mixnode.address,
            _ => panic!("The next route element must be a mix node"),
        };
        let routing_info_components = [
            next_node_hop_address.to_vec(),
            routing_info_mac.to_vec(),
            routing_info,
        ]
        .concat()
        .to_vec();

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &routing_keys[i].stream_cipher_key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        routing_info = utils::bytes::xor(
            &routing_info_components,
            &pseudorandom_bytes[..(2 * MAX_PATH_LENGTH - 1) * SECURITY_PARAMETER],
        );
    }
    let mut routing_info_mac: Vec<u8> = crypto::compute_keyed_hmac(
        routing_keys[0].header_integrity_hmac_key.to_vec(),
        &routing_info,
    );
    routing_info_mac.truncate(INTEGRITY_MAC_SIZE);
    RoutingInfo {
        enc_header: routing_info,
        header_integrity_hmac: routing_info_mac,
    }
}

fn generate_final_routing_info(
    filler: Vec<u8>,
    route_len: usize,
    destination: &Destination,
    pseudorandom_bytes: Vec<u8>,
) -> Vec<u8> {
    let address_bytes = destination.address;
    let surbidentifier = destination.identifier;
    let final_destination_bytes = [address_bytes.to_vec(), surbidentifier.to_vec()].concat();

    assert!(address_bytes.len() <= (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER);

    let padding = bytes::random(
        (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER - address_bytes.len(),
    );

    let padded_final_destination = [final_destination_bytes.to_vec(), padding].concat();
    let xored_bytes = utils::bytes::xor(
        &padded_final_destination,
        &pseudorandom_bytes[0..((2 * (MAX_PATH_LENGTH - route_len) + 3) * SECURITY_PARAMETER)],
    );
    [xored_bytes, filler].concat()
}

#[cfg(test)]
speculate! {
    describe "encapsulation of the final routing information" {
        context "for route of length 5"{
            it "produces result of length filler plus padded concatenated destination and identifier" {
                let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
                let route_len = 5;
                let filler = filler_fixture(route_len-1);
                let destination = Destination {
                    pub_key: crypto::generate_random_curve_point(),
                    address: address_fixture(),
                    identifier: [42u8;SECURITY_PARAMETER]
                };
                let filler_len = filler.len();
                let destination_address = &destination.address;
                let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
                let expected_final_header_len = DESTINATION_LENGTH + IDENTIFIER_LENGTH + (2*(MAX_PATH_LENGTH-route_len)+2)*SECURITY_PARAMETER-DESTINATION_LENGTH + filler_len;
                assert_eq!(expected_final_header_len, final_header.len());
            }
        }
    }
    context "for route of length 3"{
        it "produces result of length filler plus padded concatenated destination and identifier" {
            let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
            let route_len = 3;
            let filler = filler_fixture(route_len-1);
            let destination = Destination {
                pub_key: crypto::generate_random_curve_point(),
                address: address_fixture(),
                identifier: [42u8;SECURITY_PARAMETER]
            };
            let filler_len = filler.len();
            let destination_address = &destination.address;
            let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
            let expected_final_header_len = DESTINATION_LENGTH + IDENTIFIER_LENGTH + (2*(MAX_PATH_LENGTH-route_len)+2)*SECURITY_PARAMETER-DESTINATION_LENGTH + filler_len;
            assert_eq!(expected_final_header_len, final_header.len());
        }
    }
    context "for route of length 1"{
        it "produces result of length filler plus padded concatenated destination and identifier" {
            let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
            let route_len = 1;
            let filler = filler_fixture(route_len-1);
            let destination = Destination {
                pub_key: crypto::generate_random_curve_point(),
                address: address_fixture(),
                identifier: [42u8;SECURITY_PARAMETER]
            };
            let filler_len = filler.len();
            let destination_address = &destination.address;
            let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
            let expected_final_header_len = DESTINATION_LENGTH + IDENTIFIER_LENGTH + (2*(MAX_PATH_LENGTH-route_len)+2)*SECURITY_PARAMETER-DESTINATION_LENGTH + filler_len;
            assert_eq!(expected_final_header_len, final_header.len());
        }
    }
    context "for route of length 0"{
        #[should_panic]
        it "panics" {
            let pseudorandom_bytes = vec![0; STREAM_CIPHER_OUTPUT_LENGTH];
            let route_len = 0;
            let filler = filler_fixture(route_len-1);
            let destination = Destination {
                pub_key: crypto::generate_random_curve_point(),
                address: address_fixture(),
                identifier: [42u8;SECURITY_PARAMETER]
            };
            let filler_len = filler.len();
            let destination_address = &destination.address;
            let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
        }
    }
    describe "encapsulation of the all the routing information and integrity macs"{
        context "foomp"{
        }
    }
}

pub fn address_fixture() -> AddressBytes {
    [0u8; 32]
}

pub fn surbidentifier_fixture() -> SURBIdentifier {
    [0u8; SECURITY_PARAMETER]
}

fn filler_fixture(i: usize) -> Vec<u8> {
    vec![0u8; 2 * SECURITY_PARAMETER * i]
}
