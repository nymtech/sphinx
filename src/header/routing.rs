use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, INTEGRITY_MAC_KEY_SIZE, INTEGRITY_MAC_SIZE,
    MAX_PATH_LENGTH, PAYLOAD_KEY_SIZE, SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::header::{Destination, NodeAddressBytes, RouteElement};
use crate::utils;
use crate::utils::crypto;
use crate::utils::crypto::{STREAM_CIPHER_INIT_VECTOR, STREAM_CIPHER_KEY_SIZE};

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    ROUTING_INFO_SIZE - DESTINATION_ADDRESS_LENGTH - IDENTIFIER_LENGTH;
pub const ROUTING_INFO_SIZE: usize = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

pub type StreamCipherKey = [u8; STREAM_CIPHER_KEY_SIZE];
pub type HeaderIntegrityMacKey = [u8; INTEGRITY_MAC_KEY_SIZE];
pub type PayloadKey = [u8; PAYLOAD_KEY_SIZE];

#[derive(Debug, PartialEq, Clone)]
pub struct RoutingKeys {
    pub stream_cipher_key: StreamCipherKey,
    pub header_integrity_hmac_key: HeaderIntegrityMacKey,
    pub payload_key: PayloadKey,
}

type RoutingInformation = [u8; ROUTING_INFO_SIZE];
type HeaderIntegrityMac = [u8; INTEGRITY_MAC_SIZE];

pub struct RoutingInfo {
    pub enc_header: RoutingInformation,
    pub header_integrity_hmac: HeaderIntegrityMac,
}

struct HeaderLayerComponents {
    // in paper beta
    pub enc_header: RoutingInformation,
    // in paper beta
    pub header_integrity_hmac: HeaderIntegrityMac,
}

pub fn generate_all_routing_info(
    route: &[RouteElement],
    routing_keys: &[RoutingKeys],
    filler_string: Vec<u8>,
) -> RoutingInfo {
    assert_eq!(route.len(), routing_keys.len());

    let final_keys = routing_keys
        .last()
        .expect("The keys should be already initialized");
    let final_hop = match route.last().expect("The route should not be empty") {
        RouteElement::FinalHop(destination) => destination,
        _ => panic!("The last route element must be a destination"),
    };

    let final_routing_info =
        generate_final_routing_info(filler_string, route.len(), &final_hop, final_keys);

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
    let outer_header_layer_components = route
        .iter()
        .take(route.len() - 1) // we don't want the last element as we already created header for it - the final header
        .map(|route_element| match route_element {
            RouteElement::ForwardHop(mixnode) => mixnode.address,
            _ => panic!("The next route element must be a mix node"),
        }) // we only care about 'address' field from the route + we implicitly check if the route has only forward hops
        .zip(
            // we need both route (i.e. address field) and corresponding keys
            routing_keys.iter().take(routing_keys.len() - 1), // again, we don't want last element
        )
        .rev() // we from from the 'inside'
        .fold(
            final_header_layer_components, // we start from the already created final routing info and mac for the destination
            |inner_layer_components, (current_node_hop_address, current_node_routing_keys)| {
                // we return routing_info and mac of this layer
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
    hop_address: NodeAddressBytes,
    routing_keys: &RoutingKeys,
    inner_layer_components: HeaderLayerComponents,
) -> HeaderLayerComponents {
    // concatenate address || previous hmac || previous routing info
    let routing_info_components: Vec<_> = hop_address
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
        encrypt_routing_info(routing_keys.stream_cipher_key, &routing_info_components);

    // compute hmac for that 'layer'
    let routing_info_integrity_mac =
        generate_routing_info_integrity_mac(routing_keys.header_integrity_hmac_key, routing_info);

    HeaderLayerComponents {
        enc_header: routing_info,
        header_integrity_hmac: routing_info_integrity_mac,
    }
}

fn encrypt_routing_info(
    key: StreamCipherKey,
    routing_info_components: &[u8],
) -> RoutingInformation {
    assert_eq!(ROUTING_INFO_SIZE, routing_info_components.len());

    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
        &key,
        &STREAM_CIPHER_INIT_VECTOR,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );

    let encrypted_routing_info_vec = utils::bytes::xor(
        &routing_info_components,
        &pseudorandom_bytes[..ROUTING_INFO_SIZE],
    );

    let mut encrypted_routing_info = [0u8; ROUTING_INFO_SIZE];
    encrypted_routing_info.copy_from_slice(&encrypted_routing_info_vec);
    encrypted_routing_info
}

fn generate_routing_info_integrity_mac(
    key: HeaderIntegrityMacKey,
    data: RoutingInformation,
) -> HeaderIntegrityMac {
    let routing_info_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
    let mut integrity_mac = [0u8; INTEGRITY_MAC_SIZE];
    integrity_mac.copy_from_slice(&routing_info_mac[..INTEGRITY_MAC_SIZE]);
    integrity_mac
}

fn encrypt_padded_final_destination(
    key: StreamCipherKey,
    padded_final_destination: &[u8],
    route_len: usize,
) -> Vec<u8> {
    assert_eq!(
        ((3 * (MAX_PATH_LENGTH - route_len) + 3) * SECURITY_PARAMETER),
        padded_final_destination.len()
    );

    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
        &key,
        &STREAM_CIPHER_INIT_VECTOR,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );

    utils::bytes::xor(
        padded_final_destination,
        &pseudorandom_bytes[..((3 * (MAX_PATH_LENGTH - route_len) + 3) * SECURITY_PARAMETER)],
    )
}

fn generate_final_routing_info(
    filler: Vec<u8>,
    route_len: usize,
    destination: &Destination,
    final_keys: &RoutingKeys,
) -> RoutingInformation {
    let address_bytes = destination.address;
    let surb_identifier = destination.identifier;
    let final_destination_bytes = [address_bytes.to_vec(), surb_identifier.to_vec()].concat();

    assert!(address_bytes.len() <= (3 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER);
    assert!(filler.len() == 3 * SECURITY_PARAMETER * (route_len - 1));
    let padding = utils::bytes::random(
        (3 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER - address_bytes.len(),
    );
    let padded_final_destination = [final_destination_bytes.to_vec(), padding].concat();
    let encrypted_final_destination = encrypt_padded_final_destination(
        final_keys.stream_cipher_key,
        &padded_final_destination,
        route_len,
    );

    let final_routing_info_vec = [encrypted_final_destination, filler].concat();
    assert_eq!(final_routing_info_vec.len(), ROUTING_INFO_SIZE);
    let mut final_routing_information = [0u8; ROUTING_INFO_SIZE];
    final_routing_information.copy_from_slice(&final_routing_info_vec[..ROUTING_INFO_SIZE]);
    final_routing_information
}

// UNCOMMENT ONCE WE FIX OUR LENGTH ISSUE
//
#[cfg(test)]
mod preparing_header_layer {
    use super::*;
    use crate::header::header::node_address_fixture;

    #[test]
    fn returns_encrypted_truncated_address_concatenated_with_inner_layer_and_mac_on_it() {
        let address = node_address_fixture();
        let routing_keys = routing_keys_fixture();
        let inner_layer_components = header_layer_components_fixture();

        let concatenated_materials: Vec<u8> = [
            address.to_vec(),
            inner_layer_components.header_integrity_hmac.to_vec(),
            inner_layer_components
                .enc_header
                .to_vec()
                .iter()
                .cloned()
                .take(TRUNCATED_ROUTING_INFO_SIZE)
                .collect(),
        ]
        .concat();

        let next_layer_components =
            prepare_header_layer(address, &routing_keys, inner_layer_components);
        let expected_routing_info =
            encrypt_routing_info(routing_keys.stream_cipher_key, &concatenated_materials);
        let expected_integrity_mac = generate_routing_info_integrity_mac(
            routing_keys.header_integrity_hmac_key,
            expected_routing_info,
        );

        assert_eq!(
            expected_routing_info.to_vec(),
            next_layer_components.enc_header.to_vec()
        );
        assert_eq!(
            expected_integrity_mac.to_vec(),
            next_layer_components.header_integrity_hmac.to_vec()
        );
    }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information {
    use super::*;
    use crate::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH};
    use crate::header::filler::filler_fixture;
    use crate::header::header::{destination_address_fixture, surb_identifier_fixture};

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_5(
    ) {
        let final_leys = routing_keys_fixture();
        let route_len = 5;
        let filler = filler_fixture(route_len - 1);
        let destination = Destination {
            pub_key: crypto::generate_random_curve_point(),
            address: destination_address_fixture(),
            identifier: surb_identifier_fixture(),
        };
        let filler_len = filler.len();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_leys);

        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

        assert_eq!(expected_final_header_len, final_header.len());
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_3(
    ) {
        let final_leys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len - 1);
        let destination = Destination {
            pub_key: crypto::generate_random_curve_point(),
            address: destination_address_fixture(),
            identifier: surb_identifier_fixture(),
        };
        let filler_len = filler.len();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_leys);
        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;
        assert_eq!(expected_final_header_len, final_header.len());
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_1(
    ) {
        let final_leys = routing_keys_fixture();
        let route_len = 1;
        let filler = filler_fixture(route_len - 1);
        let destination = Destination {
            pub_key: crypto::generate_random_curve_point(),
            address: destination_address_fixture(),
            identifier: surb_identifier_fixture(),
        };
        let filler_len = filler.len();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_leys);
        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;
        assert_eq!(expected_final_header_len, final_header.len());
    }

    #[test]
    #[should_panic]
    fn it_panics_route_of_length_0() {
        let final_leys = routing_keys_fixture();
        let route_len = 0;
        let filler = filler_fixture(route_len);
        let destination = Destination {
            pub_key: crypto::generate_random_curve_point(),
            address: destination_address_fixture(),
            identifier: surb_identifier_fixture(),
        };
        let filler_len = filler.len();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_leys);
    }
}

#[cfg(test)]
mod encrypting_routing_information {
    use super::*;

    #[test]
    fn it_is_possible_to_decrypt_it_to_recover_original_data() {
        let key = [2u8; STREAM_CIPHER_KEY_SIZE];
        let data = vec![3u8; ROUTING_INFO_SIZE];
        let encrypted_data = encrypt_routing_info(key, &data);
        let decryption_key_source = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let decryption_key = &decryption_key_source[..ROUTING_INFO_SIZE];
        let decrypted_data = utils::bytes::xor(&encrypted_data, decryption_key);
        assert_eq!(data, decrypted_data);
    }
}

#[cfg(test)]
mod computing_integrity_mac {
    use super::*;

    #[test]
    fn it_is_possible_to_verify_correct_mac() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let data = [3u8; ROUTING_INFO_SIZE];
        let integrity_mac = generate_routing_info_integrity_mac(key, data);

        let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
        computed_mac.truncate(INTEGRITY_MAC_SIZE);
        assert_eq!(computed_mac, integrity_mac);
    }

    #[test]
    fn it_lets_detecting_flipped_data_bits() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let mut data = [3u8; ROUTING_INFO_SIZE];
        let integrity_mac = generate_routing_info_integrity_mac(key, data);
        data[10] = !data[10];
        let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
        computed_mac.truncate(INTEGRITY_MAC_SIZE);
        assert_ne!(computed_mac, integrity_mac);
    }
}

pub fn routing_keys_fixture() -> RoutingKeys {
    RoutingKeys {
        stream_cipher_key: [1u8; crypto::STREAM_CIPHER_KEY_SIZE],
        header_integrity_hmac_key: [2u8; INTEGRITY_MAC_KEY_SIZE],
        payload_key: [3u8; PAYLOAD_KEY_SIZE],
    }
}

fn header_layer_components_fixture() -> HeaderLayerComponents {
    HeaderLayerComponents {
        enc_header: [5u8; ROUTING_INFO_SIZE],
        header_integrity_hmac: [6u8; INTEGRITY_MAC_SIZE],
    }
}
