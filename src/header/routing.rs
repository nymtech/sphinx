use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, HEADER_INTEGRITY_MAC_SIZE, IDENTIFIER_LENGTH, MAX_PATH_LENGTH,
    SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::filler::Filler;
use crate::header::header::{
    Destination, DestinationAddressBytes, NodeAddressBytes, RouteElement, SURBIdentifier,
};
use crate::header::keys::{HeaderIntegrityMacKey, RoutingKeys, StreamCipherKey};
use crate::utils;
use crate::utils::crypto;
use crate::utils::crypto::STREAM_CIPHER_INIT_VECTOR;

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    ENCRYPTED_ROUTING_INFO_SIZE - DESTINATION_ADDRESS_LENGTH - IDENTIFIER_LENGTH;
pub const ENCRYPTED_ROUTING_INFO_SIZE: usize = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

#[derive(Debug)]
pub enum RoutingEncapsulationError {
    IsNotForwardHopError,
    IsNotFinalHopError,
    EmptyRouteError,
    EmptyKeysError,
    UnequalRouteAndKeysError,
}

// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
pub struct EncapsulatedRoutingInformation {
    enc_routing_information: EncryptedRoutingInformation,
    integrity_mac: HeaderIntegrityMac,
}

impl EncapsulatedRoutingInformation {
    pub fn new(
        route: &[RouteElement],
        routing_keys: &[RoutingKeys],
        filler: Filler,
    ) -> Result<Self, RoutingEncapsulationError> {
        if route.len() != routing_keys.len() {
            return Err(RoutingEncapsulationError::UnequalRouteAndKeysError);
        }
        let final_keys = match routing_keys.last() {
            Some(k) => k,
            None => return Err(RoutingEncapsulationError::EmptyKeysError),
        };
        let final_hop = match route.last() {
            Some(k) => k,
            None => return Err(RoutingEncapsulationError::EmptyRouteError),
        };

        // TODO: proper error wrapping for below
        let final_encapsulated_routing_info =
            Self::for_final_hop(final_hop, final_keys, filler, route.len()).unwrap();

        Ok(Self::for_forward_hops(
            final_encapsulated_routing_info,
            route,
            routing_keys,
        ))
    }

    fn for_final_hop(
        destination_hop: &RouteElement,
        routing_keys: &RoutingKeys,
        filler: Filler,
        route_len: usize,
    ) -> Result<Self, RoutingEncapsulationError> {
        let destination = match destination_hop {
            RouteElement::FinalHop(dest) => dest,
            _ => return Err(RoutingEncapsulationError::IsNotFinalHopError),
        };

        // personal note: I like how this looks so much.
        Ok(FinalRoutingInformation::new(destination, route_len)
            .add_padding(route_len)
            .encrypt(routing_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len)
            .encapsulate_with_mac(routing_keys.header_integrity_hmac_key))
    }

    fn for_forward_hops(
        final_encapsulated_routing_info: Self,
        route: &[RouteElement],
        routing_keys: &[RoutingKeys],
    ) -> Self {
        route
            .iter()
            .take(route.len() - 1) // we don't want the last element as we already created routing information for it
            .zip(
                // we need both route (i.e. address field) and corresponding keys
                routing_keys.iter().take(routing_keys.len() - 1), // again, we don't want last element
            )
            .rev() // we from from the 'inside'
            .fold(
                final_encapsulated_routing_info, // we start from the already created encrypted final routing info and mac for the destination
                |next_encapsulated_routing_information,
                 (current_node_route_element, current_node_routing_keys)| {
                    RoutingInformation::new(
                        current_node_route_element,
                        next_encapsulated_routing_information,
                    )
                    .unwrap()
                    .encrypt(current_node_routing_keys.stream_cipher_key)
                    .encapsulate_with_mac(current_node_routing_keys.header_integrity_hmac_key)
                },
            )
    }
}

// In paper gamma
// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
pub struct HeaderIntegrityMac {
    value: [u8; HEADER_INTEGRITY_MAC_SIZE],
}

impl HeaderIntegrityMac {
    // TODO: perhaps change header_data to concrete type? (but then we have issue with ownership)
    fn compute(key: HeaderIntegrityMacKey, header_data: &[u8]) -> Self {
        let routing_info_mac = crypto::compute_keyed_hmac(key.to_vec(), &header_data);
        let mut integrity_mac = [0u8; HEADER_INTEGRITY_MAC_SIZE];
        integrity_mac.copy_from_slice(&routing_info_mac[..HEADER_INTEGRITY_MAC_SIZE]);
        Self {
            value: integrity_mac,
        }
    }

    fn get_value(self) -> [u8; HEADER_INTEGRITY_MAC_SIZE] {
        self.value
    }
}

// In paper beta
struct RoutingInformation {
    node_address: NodeAddressBytes,
    // in paper nu
    header_integrity_mac: HeaderIntegrityMac,
    // in paper gamma
    next_routing_information: TruncatedRoutingInformation, // in paper also beta
}

impl RoutingInformation {
    fn new(
        route_element: &RouteElement,
        next_encapsulated_routing_information: EncapsulatedRoutingInformation,
    ) -> Result<Self, RoutingEncapsulationError> {
        let node_address = match route_element {
            RouteElement::ForwardHop(mixnode) => mixnode.address,
            _ => return Err(RoutingEncapsulationError::IsNotForwardHopError),
        };

        Ok(RoutingInformation {
            node_address,
            header_integrity_mac: next_encapsulated_routing_information.integrity_mac,
            next_routing_information: next_encapsulated_routing_information
                .enc_routing_information
                .truncate(),
        })
    }

    fn concatenate_components(self) -> Vec<u8> {
        self.node_address
            .iter()
            .cloned()
            .chain(self.header_integrity_mac.get_value().iter().cloned())
            .chain(self.next_routing_information.iter().cloned())
            .collect()
    }

    fn encrypt(self, key: StreamCipherKey) -> EncryptedRoutingInformation {
        let routing_info_components = self.concatenate_components();
        assert_eq!(ENCRYPTED_ROUTING_INFO_SIZE, routing_info_components.len());

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        let encrypted_routing_info_vec = utils::bytes::xor(
            &routing_info_components,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );

        let mut encrypted_routing_info = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        encrypted_routing_info.copy_from_slice(&encrypted_routing_info_vec);

        dbg!(routing_info_components);
        //        println!(
        //            "before: {:?}; prng: {:?} after: {:?}",
        //            routing_info_components, pseudorandom_bytes, encrypted_routing_info_vec
        //        );

        EncryptedRoutingInformation {
            value: encrypted_routing_info,
        }
    }
}

// result of xoring beta with rho (output of PRNG)
// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
pub struct EncryptedRoutingInformation {
    value: [u8; ENCRYPTED_ROUTING_INFO_SIZE],
}

impl EncryptedRoutingInformation {
    fn truncate(self) -> TruncatedRoutingInformation {
        let mut truncated_routing_info = [0u8; TRUNCATED_ROUTING_INFO_SIZE];
        truncated_routing_info.copy_from_slice(&self.value[..TRUNCATED_ROUTING_INFO_SIZE]);
        truncated_routing_info
    }

    fn get_value(self) -> [u8; ENCRYPTED_ROUTING_INFO_SIZE] {
        self.value
    }

    fn encapsulate_with_mac(self, key: HeaderIntegrityMacKey) -> EncapsulatedRoutingInformation {
        let integrity_mac = HeaderIntegrityMac::compute(key, &self.value);
        EncapsulatedRoutingInformation {
            enc_routing_information: self,
            integrity_mac,
        }
    }
}

// result of truncating encrypted beta before passing it to next 'layer'
type TruncatedRoutingInformation = [u8; TRUNCATED_ROUTING_INFO_SIZE];

// this is going through the following transformations:
/*
    FinalRoutingInformation -> PaddedFinalRoutingInformation -> EncryptedPaddedFinalRoutingInformation ->
    Encrypted Padded Destination with Filler - this can be treated as EncryptedRoutingInformation
*/

// TODO: perhaps add route_len to all final_routing_info related structs to simplify everything?
// because it seems weird that say 'encrypt' requires route_len argument
struct FinalRoutingInformation {
    destination: DestinationAddressBytes,
    // in paper delta
    identifier: SURBIdentifier, // in paper I
}

impl FinalRoutingInformation {
    // TODO: this should really return a Result in case the assertion failed
    fn new(dest: &Destination, route_len: usize) -> Self {
        assert!(dest.address.len() <= Self::max_destination_length(route_len));

        Self {
            destination: dest.address,
            identifier: dest.identifier,
        }
    }

    fn max_destination_length(route_len: usize) -> usize {
        (3 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER
    }

    fn max_padded_destination_identifier_length(route_len: usize) -> usize {
        // this should evaluate to (3 * (MAX_PATH_LENGTH - route_len) + 3) * SECURITY_PARAMETER
        Self::max_destination_length(route_len) + IDENTIFIER_LENGTH
    }

    fn add_padding(self, route_len: usize) -> PaddedFinalRoutingInformation {
        // paper uses 0 bytes for this, however, we use random instead so that we would not be affected by the
        // attack on sphinx described by Kuhn et al.
        let padding =
            utils::bytes::random(Self::max_destination_length(route_len) - self.destination.len());

        // return D || I || PAD
        PaddedFinalRoutingInformation {
            value: self
                .destination
                .iter()
                .cloned()
                .chain(self.identifier.iter().cloned())
                .chain(padding.iter().cloned())
                .collect(),
        }
    }
}

// in paper D || I || 0
struct PaddedFinalRoutingInformation {
    value: Vec<u8>,
}

impl PaddedFinalRoutingInformation {
    fn encrypt(
        self,
        key: StreamCipherKey,
        route_len: usize,
    ) -> EncryptedPaddedFinalRoutingInformation {
        assert_eq!(
            FinalRoutingInformation::max_padded_destination_identifier_length(route_len),
            self.value.len()
        );

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        EncryptedPaddedFinalRoutingInformation {
            value: utils::bytes::xor(
                &self.value,
                &pseudorandom_bytes[..self.value.len()], // we already asserted it has correct length
            ),
        }
    }
}

// in paper XOR ( (D || I || 0), rho(h_{rho}(s)) )
struct EncryptedPaddedFinalRoutingInformation {
    value: Vec<u8>,
}

impl EncryptedPaddedFinalRoutingInformation {
    // technically it's not exactly EncryptedRoutingInformation
    // as it's EncryptedPaddedFinalRoutingInformation with possibly concatenated filler string
    // however, for all of our purposes, it behaves exactly like EncryptedRoutingInformation
    fn combine_with_filler(self, filler: Filler, route_len: usize) -> EncryptedRoutingInformation {
        let filler_value = filler.get_value();
        assert_eq!(filler_value.len(), 3 * SECURITY_PARAMETER * (route_len - 1));

        let final_routing_info_vec: Vec<u8> =
            self.value.iter().cloned().chain(filler_value).collect();

        // sanity check assertion, because we're using vectors
        assert_eq!(final_routing_info_vec.len(), ENCRYPTED_ROUTING_INFO_SIZE);
        let mut final_routing_information = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        final_routing_information
            .copy_from_slice(&final_routing_info_vec[..ENCRYPTED_ROUTING_INFO_SIZE]);
        EncryptedRoutingInformation {
            value: final_routing_information,
        }
    }
}

// TODO: all tests were retrofitted to work with new code structure,
// they should be rewritten to work better with what we have now.

#[cfg(test)]
mod encapsulating_all_routing_information {
    use crate::header::filler::filler_fixture;
    use crate::header::header::{random_final_hop, random_forward_hop};
    use crate::header::keys::routing_keys_fixture;

    use super::*;

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

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
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

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_empty_route_is_provided() {
        let route = vec![];
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_panic_if_empty_keys_are_provided() {
        let route = [random_forward_hop(), random_final_hop()];
        let keys = vec![];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }
}

#[cfg(test)]
mod encapsulating_forward_routing_information {
    use crate::header::filler::filler_fixture;
    use crate::header::header::{random_final_hop, random_forward_hop};
    use crate::header::keys::routing_keys_fixture;

    use super::*;

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_length_3() {
        // this is basically loop unwrapping, but considering the complex logic behind it, it's warranted
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
        let filler_copy = filler_fixture(route.len() - 1);
        assert_eq!(filler, filler_copy);

        let final_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &route.last().unwrap(),
            &routing_keys.last().unwrap(),
            filler,
            route.len(),
        )
        .unwrap();

        let final_routing_info_copy = final_routing_info.clone();

        // sanity check to make sure our 'copy' worked
        assert_eq!(
            final_routing_info.enc_routing_information.value.to_vec(),
            final_routing_info_copy
                .enc_routing_information
                .value
                .to_vec()
        );
        assert_eq!(
            final_routing_info.integrity_mac.value.to_vec(),
            final_routing_info_copy.integrity_mac.value.to_vec()
        );

        let routing_info = EncapsulatedRoutingInformation::for_forward_hops(
            final_routing_info,
            &route,
            &routing_keys,
        );

        let layer_1_routing = RoutingInformation::new(&route[1], final_routing_info_copy)
            .unwrap()
            .encrypt(routing_keys[1].stream_cipher_key)
            .encapsulate_with_mac(routing_keys[1].header_integrity_hmac_key);

        let layer_0_routing = RoutingInformation::new(&route[0], layer_1_routing)
            .unwrap()
            .encrypt(routing_keys[0].stream_cipher_key)
            .encapsulate_with_mac(routing_keys[0].header_integrity_hmac_key);

        assert_eq!(
            routing_info.enc_routing_information.value.to_vec(),
            layer_0_routing.enc_routing_information.value.to_vec()
        );
        assert_eq!(
            routing_info.integrity_mac.value,
            layer_0_routing.integrity_mac.value
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
    use crate::header::header::{node_address_fixture, MixNode};
    use crate::header::keys::routing_keys_fixture;

    use super::*;

    #[test]
    fn it_returns_encrypted_truncated_address_concatenated_with_inner_layer_and_mac_on_it() {
        let address = node_address_fixture();
        let forward_hop = RouteElement::ForwardHop(MixNode {
            address,
            pub_key: Default::default(),
        });

        let routing_keys = routing_keys_fixture();
        let inner_layer_routing = encapsulated_routing_information_fixture();

        // calculate everything without using any object methods
        let concatenated_materials: Vec<u8> = [
            address.to_vec(),
            inner_layer_routing.integrity_mac.value.to_vec(),
            inner_layer_routing
                .enc_routing_information
                .value
                .to_vec()
                .iter()
                .cloned()
                .take(TRUNCATED_ROUTING_INFO_SIZE)
                .collect(),
        ]
        .concat();

        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &routing_keys.stream_cipher_key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );

        let expected_encrypted_routing_info_vec = utils::bytes::xor(
            &concatenated_materials,
            &pseudorandom_bytes[..ENCRYPTED_ROUTING_INFO_SIZE],
        );

        let mut expected_routing_mac = crypto::compute_keyed_hmac(
            routing_keys.header_integrity_hmac_key.to_vec(),
            &expected_encrypted_routing_info_vec,
        );
        expected_routing_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);

        let next_layer_routing = RoutingInformation::new(&forward_hop, inner_layer_routing)
            .unwrap()
            .encrypt(routing_keys.stream_cipher_key)
            .encapsulate_with_mac(routing_keys.header_integrity_hmac_key);

        assert_eq!(
            expected_encrypted_routing_info_vec,
            next_layer_routing.enc_routing_information.value.to_vec()
        );
        assert_eq!(expected_routing_mac, next_layer_routing.integrity_mac.value);
    }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information_and_mac {
    use super::*;
    use crate::header::filler::filler_fixture;
    use crate::header::header::{random_final_hop, random_forward_hop};
    use crate::header::keys::routing_keys_fixture;

    #[test]
    #[should_panic]
    fn it_panics_if_the_route_element_is_not_a_final_hop() {
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
        EncapsulatedRoutingInformation::for_final_hop(
            &route.last().unwrap(),
            &routing_keys.last().unwrap(),
            filler,
            route.len(),
        )
        .unwrap();
    }

    #[test]
    fn it_returns_mac_on_correct_data() {
        // this test is created to ensure we MAC the encrypted data BEFORE it is truncated
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
        let final_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &route.last().unwrap(),
            &routing_keys.last().unwrap(),
            filler,
            route.len(),
        )
        .unwrap();

        let expected_mac = HeaderIntegrityMac::compute(
            routing_keys.last().unwrap().header_integrity_hmac_key,
            &final_routing_info.enc_routing_information.value,
        );
        assert_eq!(expected_mac.value, final_routing_info.integrity_mac.value);
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

        let final_routing_header = FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);

        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

        assert_eq!(expected_final_header_len, final_routing_header.value.len());
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_3(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();

        let final_routing_header = FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);

        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

        assert_eq!(expected_final_header_len, final_routing_header.value.len());
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_for_route_of_length_1(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 1;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();

        let final_routing_header = FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);

        let expected_final_header_len = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

        assert_eq!(expected_final_header_len, final_routing_header.value.len());
    }

    #[test]
    #[should_panic]
    fn it_panics_route_of_length_0() {
        let final_keys = routing_keys_fixture();
        let route_len = 0;
        let filler = filler_fixture(route_len - 1);
        let destination = random_destination();

        FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_it_receives_filler_different_than_3i_security_parameter() {
        let final_keys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len);
        let destination = random_destination();

        FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);
    }
}

#[cfg(test)]
mod encrypting_routing_information {
    use super::*;
    use crate::header::header::node_address_fixture;
    use crate::utils::crypto::STREAM_CIPHER_KEY_SIZE;

    #[test]
    fn it_is_possible_to_decrypt_it_to_recover_original_data() {
        let key = [2u8; STREAM_CIPHER_KEY_SIZE];
        let address = node_address_fixture();
        let mac = header_integrity_mac_fixture();
        let next_routing = [8u8; TRUNCATED_ROUTING_INFO_SIZE];

        let encryption_data =
            [address.to_vec(), mac.value.to_vec(), next_routing.to_vec()].concat();

        let routing_information = RoutingInformation {
            node_address: address,
            header_integrity_mac: mac,
            next_routing_information: next_routing,
        };

        let encrypted_data = routing_information.encrypt(key);
        let decryption_key_source = crypto::generate_pseudorandom_bytes(
            &key,
            &STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let decryption_key = &decryption_key_source[..ENCRYPTED_ROUTING_INFO_SIZE];
        let decrypted_data = utils::bytes::xor(&encrypted_data.value, decryption_key);
        assert_eq!(encryption_data, decrypted_data);
    }
}

#[cfg(test)]
mod truncating_routing_information {
    use super::*;

    #[test]
    fn it_does_not_change_prefixed_data() {
        let encrypted_routing_info = encrypted_routing_information_fixture();
        let routing_info_data_copy = encrypted_routing_info.value.clone();

        let truncated_routing_info = encrypted_routing_info.truncate();
        for i in 0..truncated_routing_info.len() {
            assert_eq!(truncated_routing_info[i], routing_info_data_copy[i]);
        }
    }
}

#[cfg(test)]
mod computing_integrity_mac {
    use super::*;
    use crate::constants::INTEGRITY_MAC_KEY_SIZE;

    #[test]
    fn it_is_possible_to_verify_correct_mac() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);

        let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
        computed_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);
        assert_eq!(computed_mac, integrity_mac.value);
    }

    #[test]
    fn it_lets_detecting_flipped_data_bits() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let mut data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);
        data[10] = !data[10];
        let mut computed_mac = crypto::compute_keyed_hmac(key.to_vec(), &data.to_vec());
        computed_mac.truncate(HEADER_INTEGRITY_MAC_SIZE);
        assert_ne!(computed_mac, integrity_mac.value);
    }
}

pub fn header_integrity_mac_fixture() -> HeaderIntegrityMac {
    HeaderIntegrityMac {
        value: [6u8; HEADER_INTEGRITY_MAC_SIZE],
    }
}

pub fn encrypted_routing_information_fixture() -> EncryptedRoutingInformation {
    EncryptedRoutingInformation {
        value: [5u8; ENCRYPTED_ROUTING_INFO_SIZE],
    }
}

pub fn encapsulated_routing_information_fixture() -> EncapsulatedRoutingInformation {
    EncapsulatedRoutingInformation {
        enc_routing_information: encrypted_routing_information_fixture(),
        integrity_mac: header_integrity_mac_fixture(),
    }
}
