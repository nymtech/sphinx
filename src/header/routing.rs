use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, INTEGRITY_MAC_KEY_SIZE, INTEGRITY_MAC_SIZE,
    MAX_PATH_LENGTH, PAYLOAD_KEY_SIZE, SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::header::{Destination, NodeAddressBytes, RouteElement};
use crate::header::keys::{HeaderIntegrityMacKey, RoutingKeys, StreamCipherKey};
use crate::utils;
use crate::utils::crypto;
use crate::utils::crypto::{STREAM_CIPHER_INIT_VECTOR, STREAM_CIPHER_KEY_SIZE};

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    ROUTING_INFO_SIZE - DESTINATION_ADDRESS_LENGTH - IDENTIFIER_LENGTH;
pub const ROUTING_INFO_SIZE: usize = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

type RoutingInformation = [u8; ROUTING_INFO_SIZE];
type HeaderIntegrityMac = [u8; INTEGRITY_MAC_SIZE];

pub struct RoutingInfo {
    pub enc_header: RoutingInformation,
    pub header_integrity_hmac: HeaderIntegrityMac,
}

#[derive(Clone)]
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

    let final_header_layer_components =
        encapsulate_final_routing_info_and_integrity_mac(route, routing_keys, filler_string);
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

fn encapsulate_final_routing_info_and_integrity_mac(
    route: &[RouteElement],
    routing_keys: &[RoutingKeys],
    filler_string: Vec<u8>,
) -> HeaderLayerComponents {
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

    HeaderLayerComponents {
        enc_header: final_routing_info,
        header_integrity_hmac: final_routing_info_mac,
    }
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

    let max_destination_length = (3 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER;
    assert!(address_bytes.len() <= max_destination_length);
    assert_eq!(filler.len(), 3 * SECURITY_PARAMETER * (route_len - 1));

    let padding = utils::bytes::random(max_destination_length - address_bytes.len());
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

#[cfg(test)]
mod encapsulating_all_routing_information {
    use super::*;
    use crate::header::filler::filler_fixture;
    use crate::header::header::{random_final_hop, random_forward_hop};
    use crate::header::keys::routing_keys_fixture;

    #[test]
    #[should_panic]
    fn it_panics_if_route_is_longer_than_keys() {
        let route = [
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];
        let keys = [routing_keys_fixture(), routing_keys_fixture()];
        let filler = filler_fixture(route.len() - 1);

        generate_all_routing_info(&route, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_keys_are_longer_than_route() {
        let route = [random_forward_hop(), random_final_hop()];
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        generate_all_routing_info(&route, &keys, filler);
    }
}

#[cfg(test)]
mod encapsulating_routing_information {
    use super::*;
    use crate::header::filler::filler_fixture;
    use crate::header::header::{random_destination, random_final_hop, random_forward_hop};
    use crate::header::keys::routing_keys_fixture;

    #[test]
    fn it_returns_final_header_components_for_route_of_length_1() {
        let route_len = 1;
        let final_keys = routing_keys_fixture();
        let destination = random_destination();
        let filler = filler_fixture(route_len - 1);

        let final_routing_info =
            generate_final_routing_info(filler, route_len, &destination, &final_keys);
        let final_routing_mac = generate_routing_info_integrity_mac(
            final_keys.header_integrity_hmac_key,
            final_routing_info,
        );
        let final_header_layer_components = HeaderLayerComponents {
            enc_header: final_routing_info,
            header_integrity_hmac: final_routing_mac,
        };

        let route = vec![RouteElement::FinalHop(destination)];
        let routing_info = encapsulate_routing_info_and_integrity_macs(
            final_header_layer_components,
            &route,
            &[final_keys],
        );

        assert_eq!(
            routing_info.enc_header.to_vec(),
            final_routing_info.to_vec()
        );
        assert_eq!(
            routing_info.header_integrity_hmac.to_vec(),
            final_routing_mac.to_vec()
        );
    }

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_length_3() {
        // this is basically loop unwrapping, but considering the complex iterator, it's warranted
        let route = [
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        let final_header_layer_components =
            encapsulate_final_routing_info_and_integrity_mac(&route, &routing_keys, filler);

        // we need to make an explicit copy of final components because they are consumed (and rightfully so) after encapsulation
        let final_header_layer_components_copy = final_header_layer_components.clone();
        let routing_info = encapsulate_routing_info_and_integrity_macs(
            final_header_layer_components,
            &route,
            &routing_keys,
        );

        let layer_2_header = prepare_header_layer(
            match &route[1] {
                RouteElement::ForwardHop(mix) => mix.address,
                _ => panic!(),
            },
            &routing_keys[1],
            final_header_layer_components_copy,
        );

        let layer_1_header = prepare_header_layer(
            match &route[0] {
                RouteElement::ForwardHop(mix) => mix.address,
                _ => panic!(),
            },
            &routing_keys[0],
            layer_2_header,
        );

        assert_eq!(
            routing_info.enc_header.to_vec(),
            layer_1_header.enc_header.to_vec()
        );
        assert_eq!(
            routing_info.header_integrity_hmac,
            layer_1_header.header_integrity_hmac
        );
    }

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_max_length() {
        // this is basically loop unwrapping, but considering the complex iterator, it's warranted
        assert_eq!(5, MAX_PATH_LENGTH); // make sure we catch it if we decided to change the constant

        /* since we're using max path length we expect literally:
        n4 || m4 || n3 || m3 || n2 || m2 || n1 || m1 || d || i || p
        // so literally no filler!
        where:
        {n1, n2, ...} are node addresses
        {m1, m2, ...} are macs on previous layers
        d is destination address
        i is destination identifier
        p is destination padding
        */

        // TODO: IMPLEMENT SPHINX HEADER LAYER UNWRAPING
        // HOWEVER! to test it, we need to first wrap function to unwrap header layer because each consequtive (ni, mi) pair is encrypted
    }
}

#[cfg(test)]
mod preparing_header_layer {
    use super::*;
    use crate::header::header::node_address_fixture;
    use crate::header::keys::routing_keys_fixture;

    #[test]
    fn it_returns_encrypted_truncated_address_concatenated_with_inner_layer_and_mac_on_it() {
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
mod test_encapsulating_final_routing_information_and_mac {
    use super::*;
    use crate::header::filler::filler_fixture;
    use crate::header::header::{random_destination, random_final_hop, random_forward_hop};
    use crate::header::keys::routing_keys_fixture;

    #[test]
    #[should_panic]
    fn it_panics_if_last_route_element_is_not_a_final_hop() {
        let route = [
            random_forward_hop(),
            random_forward_hop(),
            random_forward_hop(),
        ];
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        encapsulate_final_routing_info_and_integrity_mac(&route, &routing_keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_it_doesnt_receive_any_keys() {
        let route = [random_final_hop()];
        let routing_keys: Vec<RoutingKeys> = vec![];
        let filler = filler_fixture(route.len() - 1);
        encapsulate_final_routing_info_and_integrity_mac(&route, &routing_keys, filler);
    }

    #[test]
    fn it_returns_mac_on_correct_data() {
        let route = [
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let final_header_layer_components =
            encapsulate_final_routing_info_and_integrity_mac(&route, &routing_keys, filler);

        let expected_mac = generate_routing_info_integrity_mac(
            routing_keys.last().unwrap().header_integrity_hmac_key,
            final_header_layer_components.enc_header,
        );
        assert_eq!(
            expected_mac,
            final_header_layer_components.header_integrity_hmac
        );
    }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information {
    use super::*;
    use crate::header::filler::filler_fixture;
    use crate::header::header::random_destination;
    use crate::header::keys::routing_keys_fixture;

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_5(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 5;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_keys);

        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

        assert_eq!(expected_final_header_len, final_header.len());
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_3(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_keys);
        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;
        assert_eq!(expected_final_header_len, final_header.len());
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_1(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 1;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_keys);
        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;
        assert_eq!(expected_final_header_len, final_header.len());
    }

    #[test]
    #[should_panic]
    fn it_panics_route_of_length_0() {
        let final_keys = routing_keys_fixture();
        let route_len = 0;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();
        let final_header =
            generate_final_routing_info(filler, route_len, &destination, &final_keys);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_it_receives_filler_different_than_3i_security_parameter() {
        let final_keys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len);
        let destination = random_destination();
        generate_final_routing_info(filler, route_len, &destination, &final_keys);
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

fn header_layer_components_fixture() -> HeaderLayerComponents {
    HeaderLayerComponents {
        enc_header: [5u8; ROUTING_INFO_SIZE],
        header_integrity_hmac: [6u8; INTEGRITY_MAC_SIZE],
    }
}
