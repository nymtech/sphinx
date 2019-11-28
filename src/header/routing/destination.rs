use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, FINAL_NODE_META_INFO_LENGTH, FLAG_LENGTH, IDENTIFIER_LENGTH,
    MAX_PATH_LENGTH, SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::crypto;
use crate::crypto::STREAM_CIPHER_INIT_VECTOR;
use crate::header::filler::{Filler, FILLER_STEP_SIZE_INCREASE};
use crate::header::keys::StreamCipherKey;
use crate::header::routing::nodes::EncryptedRoutingInformation;
use crate::header::routing::{ENCRYPTED_ROUTING_INFO_SIZE, FINAL_FLAG};
use crate::route::{Destination, DestinationAddressBytes, SURBIdentifier};
use crate::utils;

// this is going through the following transformations:
/*
    FinalRoutingInformation -> PaddedFinalRoutingInformation -> EncryptedPaddedFinalRoutingInformation ->
    Encrypted Padded Destination with Filler - this can be treated as EncryptedRoutingInformation
*/

// TODO: perhaps add route_len to all final_routing_info related structs to simplify everything?
// because it seems weird that say 'encrypt' requires route_len argument
pub(super) struct FinalRoutingInformation {
    flag: u8,
    destination: DestinationAddressBytes,
    // in paper delta
    identifier: SURBIdentifier, // in paper I
}

impl FinalRoutingInformation {
    // TODO: this should really return a Result in case the assertion failed
    pub fn new(dest: &Destination, route_len: usize) -> Self {
        assert!(dest.address.len() <= Self::max_destination_length(route_len));

        Self {
            flag: FINAL_FLAG,
            destination: dest.address,
            identifier: dest.identifier,
        }
    }

    fn max_destination_length(route_len: usize) -> usize {
        (3 * (MAX_PATH_LENGTH - route_len) + 2) * SECURITY_PARAMETER
    }

    fn max_padded_destination_identifier_length(route_len: usize) -> usize {
        // this should evaluate to (3 * (MAX_PATH_LENGTH - route_len) + 3) * SECURITY_PARAMETER
        ENCRYPTED_ROUTING_INFO_SIZE - (FILLER_STEP_SIZE_INCREASE * (route_len - 1))
    }

    pub(super) fn add_padding(self, route_len: usize) -> PaddedFinalRoutingInformation {
        // paper uses 0 bytes for this, however, we use random instead so that we would not be affected by the
        // attack on sphinx described by Kuhn et al.
        let padding = utils::bytes::random(
            ENCRYPTED_ROUTING_INFO_SIZE
                - (FILLER_STEP_SIZE_INCREASE * (route_len - 1))
                - FINAL_NODE_META_INFO_LENGTH,
        );

        // return D || I || PAD
        PaddedFinalRoutingInformation {
            value: vec![self.flag]
                .iter()
                .cloned()
                .chain(self.destination.iter().cloned())
                .chain(self.identifier.iter().cloned())
                .chain(padding.iter().cloned())
                .collect(),
        }
    }
}

// in paper D || I || 0
pub(super) struct PaddedFinalRoutingInformation {
    value: Vec<u8>,
}

impl PaddedFinalRoutingInformation {
    pub(super) fn encrypt(
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
pub(super) struct EncryptedPaddedFinalRoutingInformation {
    value: Vec<u8>,
}

impl EncryptedPaddedFinalRoutingInformation {
    // technically it's not exactly EncryptedRoutingInformation
    // as it's EncryptedPaddedFinalRoutingInformation with possibly concatenated filler string
    // however, for all of our purposes, it behaves exactly like EncryptedRoutingInformation
    pub(super) fn combine_with_filler(
        self,
        filler: Filler,
        route_len: usize,
    ) -> EncryptedRoutingInformation {
        let filler_value = filler.get_value();
        assert_eq!(
            filler_value.len(),
            FILLER_STEP_SIZE_INCREASE * (route_len - 1)
        );

        let final_routing_info_vec: Vec<u8> =
            self.value.iter().cloned().chain(filler_value).collect();

        // sanity check assertion, because we're using vectors
        assert_eq!(final_routing_info_vec.len(), ENCRYPTED_ROUTING_INFO_SIZE);
        let mut final_routing_information = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];
        final_routing_information
            .copy_from_slice(&final_routing_info_vec[..ENCRYPTED_ROUTING_INFO_SIZE]);
        EncryptedRoutingInformation::from_bytes(final_routing_information)
    }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information_and_mac {
    use crate::header::filler::filler_fixture;
    use crate::header::keys::routing_keys_fixture;
    use crate::header::mac::HeaderIntegrityMac;
    use crate::header::routing::EncapsulatedRoutingInformation;
    use crate::route::{destination_fixture, random_node};

    #[test]
    fn it_returns_mac_on_correct_data() {
        // this test is created to ensure we MAC the encrypted data BEFORE it is truncated
        let route = [random_node(), random_node(), random_node()];
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let destination = destination_fixture();
        let final_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &destination,
            &routing_keys.last().unwrap(),
            filler,
            route.len(),
        );

        let expected_mac = HeaderIntegrityMac::compute(
            routing_keys.last().unwrap().header_integrity_hmac_key,
            &final_routing_info.enc_routing_information.get_value_ref(),
        );
        assert_eq!(
            expected_mac.get_value(),
            final_routing_info.integrity_mac.get_value()
        );
    }
}

#[cfg(test)]
mod test_encapsulating_final_routing_information {
    use crate::header::filler::filler_fixture;
    use crate::header::keys::routing_keys_fixture;
    use crate::route::destination_fixture;

    use super::*;

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_and_flag_for_route_of_length_5(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 5;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        let final_routing_header = FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);

        let expected_final_header_len = ENCRYPTED_ROUTING_INFO_SIZE;

        assert_eq!(
            expected_final_header_len,
            final_routing_header.get_value_ref().len()
        );
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_and_flag_for_route_of_length_3(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        let final_routing_header = FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);

        let expected_final_header_len = ENCRYPTED_ROUTING_INFO_SIZE;

        assert_eq!(
            expected_final_header_len,
            final_routing_header.get_value_ref().len()
        );
    }

    #[test]
    fn it_produces_result_of_length_filler_plus_padded_concatenated_destination_and_identifier_and_flag_for_route_of_length_1(
    ) {
        let final_keys = routing_keys_fixture();
        let route_len = 1;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        let final_routing_header = FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);

        let expected_final_header_len = ENCRYPTED_ROUTING_INFO_SIZE;

        assert_eq!(
            expected_final_header_len,
            final_routing_header.get_value_ref().len()
        );
    }

    #[test]
    #[should_panic]
    fn it_panics_route_of_length_0() {
        let final_keys = routing_keys_fixture();
        let route_len = 0;
        let filler = filler_fixture(route_len - 1);
        let destination = destination_fixture();

        FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_it_receives_filler_different_than_filler_step_multiplied_with_i() {
        let final_keys = routing_keys_fixture();
        let route_len = 3;
        let filler = filler_fixture(route_len);
        let destination = destination_fixture();

        FinalRoutingInformation::new(&destination, route_len)
            .add_padding(route_len)
            .encrypt(final_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len);
    }
}
