#[cfg(test)]
use speculate::speculate;

use crate::constants::{
    AVERAGE_DELAY, DESTINATION_LENGTH, HKDF_INPUT_SEED, IDENTIFIER_LENGTH, INTEGRITY_MAC_KEY_SIZE,
    INTEGRITY_MAC_SIZE, MAX_PATH_LENGTH, PAYLOAD_KEY_SIZE, ROUTING_KEYS_LENGTH, SECURITY_PARAMETER,
    STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::keys;
use crate::utils;
use crate::utils::bytes;
use crate::utils::crypto;
use crate::utils::crypto::{CURVE_GENERATOR, STREAM_CIPHER_INIT_VECTOR, STREAM_CIPHER_KEY_SIZE};
use itertools::Itertools;

pub const ROUTING_INFO_SIZE: usize = (2 * MAX_PATH_LENGTH - 1) * SECURITY_PARAMETER;

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
    pub payload_key: [u8; PAYLOAD_KEY_SIZE],
}

pub struct RoutingInfo {
    pub enc_header: RoutingInformation,
    pub header_integrity_hmac: HeaderIntegrityMac,
}

type RoutingInformation = [u8; ROUTING_INFO_SIZE];
type HeaderIntegrityMac = [u8; INTEGRITY_MAC_SIZE];

struct HeaderLayerComponents {
    // in paper beta
    pub enc_header: RoutingInformation,
    // in paper beta
    pub header_integrity_hmac: HeaderIntegrityMac,
}

pub(crate) fn generate_all_routing_info(
    route: &[RouteElement],
    routing_keys: &[RoutingKeys],
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

    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
        &final_keys.stream_cipher_key,
        &STREAM_CIPHER_INIT_VECTOR,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );

    let final_routing_info =
        generate_final_routing_info(filler_string, route.len(), &final_hop, pseudorandom_bytes);

    let final_routing_info_mac = generate_routing_info_integrity_mac(
        final_keys.header_integrity_hmac_key,
        final_routing_info,
    );

    let final_header_layer_components = HeaderLayerComponents {
        enc_header: final_routing_info,
        header_integrity_hmac: final_routing_info_mac,
    };

    encapsulate_routing_info_and_integrity_macs(final_header_layer_components, route, routing_keys)
}

fn encapsulate_routing_info_and_integrity_macs(
    final_header_layer_components: HeaderLayerComponents,
    route: &[RouteElement],
    routing_keys: &[RoutingKeys],
) -> RoutingInfo {
    assert_eq!(route.len(), routing_keys.len());

    let outer_header_layer_components = route
        .iter()
        .take(route.len() - 1) // we don't want the last element as we already created header for it - the final header
        .map(|route_element| match route_element {
            RouteElement::ForwardHop(mixnode) => mixnode.address,
            _ => panic!("The next route element must be a mix node"),
        }) // we only care about 'address' field from the route
        .zip(
            // we need both route (i.e. address field) and corresponding keys
            routing_keys.iter().take(routing_keys.len() - 1), // again, we don't want last element
        )
        .rev() // we from from the 'inside'
        .fold(
            final_header_layer_components, // we start from the already created final routing info and mac for the destination
            |inner_layer_components, (current_node_hop_address, current_node_routing_keys)| {
                prepare_header_layer(
                    current_node_hop_address,
                    current_node_routing_keys,
                    inner_layer_components,
                )
            },
        );

    // left for reference sake until we have decent tests for this function

//    let mut routing_info = final_routing_info;
//
//    for i in (0..route.len() - 1).rev() {
//        let routing_info_mac = generate_routing_info_integrity_mac(
//            routing_keys[i + 1].header_integrity_hmac_key,
//            &routing_info,
//        );
//
//        let next_node_hop_address = match &route[i] {
//            RouteElement::ForwardHop(mixnode) => mixnode.address,
//            _ => panic!("The next route element must be a mix node"),
//        };
//        let routing_info_components = [
//            next_node_hop_address.to_vec(),
//            routing_info_mac.to_vec(),
//            routing_info,
//        ]
//        .concat()
//        .to_vec();
//        routing_info =
//            encrypt_routing_info(routing_keys[i].stream_cipher_key, &routing_info_components);
//    }

    //    let routing_info_mac = generate_routing_info_integrity_mac(
    //        routing_keys[0].header_integrity_hmac_key,
    //        &routing_info,
    //    );
    RoutingInfo {
        enc_header: outer_header_layer_components.enc_header,
        header_integrity_hmac: outer_header_layer_components.header_integrity_hmac,
    }
}

fn prepare_header_layer(
    hop_address: AddressBytes,
    routing_keys: &RoutingKeys,
    inner_layer_components: HeaderLayerComponents,
) -> HeaderLayerComponents {
    // concatenate address || previous hmac || previous routing info
    let routing_info_components = &hop_address
        .iter()
        .cloned()
        .chain(inner_layer_components.header_integrity_hmac.iter().cloned())
        .chain(
            inner_layer_components
                .enc_header
                .iter()
                .cloned()
                .take(TRUNCATED_ROUTING_INFO_SIZE),
        ) // truncate (beta) to the desired length
        .collect();

    // encrypt (by xor'ing with output of aes keyed with our key)
    let routing_info =
        encrypt_routing_info(routing_keys.stream_cipher_key, routing_info_components);

    // compute hmac for that 'layer'
    let routing_info_integrity_mac =
        generate_routing_info_integrity_mac(routing_keys.header_integrity_hmac_key, routing_info);

    HeaderLayerComponents {
        enc_header: routing_info,
        header_integrity_hmac: routing_info_integrity_mac,
    }
}

fn encrypt_routing_info(
    key: [u8; STREAM_CIPHER_KEY_SIZE],
    routing_info_components: &Vec<u8>,
) -> Vec<u8> {
    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
        &key,
        &STREAM_CIPHER_INIT_VECTOR,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );
    utils::bytes::xor(
        &routing_info_components,
        &pseudorandom_bytes[..(2 * MAX_PATH_LENGTH - 1) * SECURITY_PARAMETER],
    )
}

fn generate_routing_info_integrity_mac(
    key: [u8; INTEGRITY_MAC_KEY_SIZE],
    data: &Vec<u8>,
) -> [u8; INTEGRITY_MAC_SIZE] {
    let routing_info_mac = crypto::compute_keyed_hmac(key.to_vec(), data);
    let mut integrity_mac = [0u8; INTEGRITY_MAC_SIZE];
    integrity_mac.copy_from_slice(&routing_info_mac[..INTEGRITY_MAC_SIZE]);
    integrity_mac
}

fn generate_final_routing_info(
    filler: Vec<u8>,
    route_len: usize,
    destination: &Destination,
    pseudorandom_bytes: Vec<u8>,
) -> Vec<u8> {
    let address_bytes = destination.address;
    let surb_identifier = destination.identifier;
    let final_destination_bytes = [address_bytes.to_vec(), surb_identifier.to_vec()].concat();

    assert!(address_bytes.len() <= (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER);

    let padding = bytes::random(
        (2 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER - address_bytes.len(),
    );

    let padded_final_destination = [final_destination_bytes.to_vec(), padding].concat();
    let xored_bytes = utils::bytes::xor(
        &padded_final_destination,
        &pseudorandom_bytes[..((2 * (MAX_PATH_LENGTH - route_len) + 3) * SECURITY_PARAMETER)],
    );

    [xored_bytes, filler].concat()
}

fn truncate_routing_info_vec(routing_info_vec: Vec<u8>) -> RoutingInformation {
    let mut final_routing_information = [0u8; ROUTING_INFO_SIZE];
    final_routing_information.copy_from_slice(&routing_info_vec[..ROUTING_INFO_SIZE]);
    final_routing_information
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
                    identifier: surb_identifier_fixture(),
                };
                let filler_len = filler.len();
                let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
                let expected_padding_len = (2*(MAX_PATH_LENGTH-route_len)+2)*SECURITY_PARAMETER-DESTINATION_LENGTH;
                let expected_final_header_len = DESTINATION_LENGTH + IDENTIFIER_LENGTH + expected_padding_len + filler_len;
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
                identifier: surb_identifier_fixture(),
            };
            let filler_len = filler.len();
            let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
            let expected_padding_len = (2*(MAX_PATH_LENGTH-route_len)+2)*SECURITY_PARAMETER-DESTINATION_LENGTH;
            let expected_final_header_len = DESTINATION_LENGTH + IDENTIFIER_LENGTH + expected_padding_len + filler_len;
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
                identifier: surb_identifier_fixture(),
            };
            let filler_len = filler.len();
            let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
            let expected_padding_len = (2*(MAX_PATH_LENGTH-route_len)+2)*SECURITY_PARAMETER-DESTINATION_LENGTH;
            let expected_final_header_len = DESTINATION_LENGTH + IDENTIFIER_LENGTH + expected_padding_len + filler_len;
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
                identifier: surb_identifier_fixture(),
            };
            let filler_len = filler.len();
            let final_header = generate_final_routing_info(filler, route_len, &destination, pseudorandom_bytes);
        }
    }
    describe "encrypt routing info"{
        it "check whether we can decrypt the result" {
            let key = [2u8; STREAM_CIPHER_KEY_SIZE];
            let data = vec![3u8; (2 * MAX_PATH_LENGTH - 1) * SECURITY_PARAMETER];
            let encrypted_data = encrypt_routing_info(key, &data);
            let decryption_key_source = crypto::generate_pseudorandom_bytes(
                &key,
                &STREAM_CIPHER_INIT_VECTOR,
                STREAM_CIPHER_OUTPUT_LENGTH);
            let decryption_key = &decryption_key_source[..(2 * MAX_PATH_LENGTH - 1) * SECURITY_PARAMETER];
            let decrypted_data = utils::bytes::xor(&encrypted_data, decryption_key);
            assert_eq!(data, decrypted_data);
        }
    }

    describe "truncating full routing information" {
        it "preserves head of original content" {
            let dummy_routing_info = bytes::random(200);
            let dummy_routing_info_copy = dummy_routing_info.to_vec();
            let truncated_routing_info = truncate_routing_info_vec(dummy_routing_info);
            for i in (0..truncated_routing_info.len()) {
                assert_eq!(truncated_routing_info[i], dummy_routing_info_copy[i])
            }
        }
    }

    describe "compute integrity mac"{
        it "check whether the integrity mac is correct"{
            let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
            let data = vec![3u8; 25];
            let integrity_mac = generate_routing_info_integrity_mac(key, &data);

            let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data);
            computed_mac.truncate(INTEGRITY_MAC_SIZE);
            assert_eq!(computed_mac, integrity_mac);
        }
        it "detects flipped bit in the data"{
            let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
            let mut data = vec![3u8; 25];
            let integrity_mac = generate_routing_info_integrity_mac(key, &data);
            data[10] = !data[10];
            let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data);
            computed_mac.truncate(INTEGRITY_MAC_SIZE);
            assert_ne!(computed_mac, integrity_mac);
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
