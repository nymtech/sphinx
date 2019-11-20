use crate::constants::{
    IDENTIFIER_LENGTH, MAX_PATH_LENGTH, SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::filler::Filler;
use crate::header::keys::StreamCipherKey;
use crate::header::routing::{EncryptedRoutingInformation, ENCRYPTED_ROUTING_INFO_SIZE};
use crate::route::{Destination, DestinationAddressBytes, SURBIdentifier};
use crate::utils;
use crate::utils::crypto;
use crate::utils::crypto::STREAM_CIPHER_INIT_VECTOR;

// TODO: perhaps add route_len to all final_routing_info related structs to simplify everything?
// because it seems weird that say 'encrypt' requires route_len argument
pub(super) struct FinalRoutingInformation {
    destination: DestinationAddressBytes,
    // in paper delta
    identifier: SURBIdentifier, // in paper I
}

impl FinalRoutingInformation {
    // TODO: this should really return a Result in case the assertion failed
    pub fn new(dest: &Destination, route_len: usize) -> Self {
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

    pub(super) fn add_padding(self, route_len: usize) -> PaddedFinalRoutingInformation {
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
