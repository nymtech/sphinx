use arrayref::array_ref;
use blake2::VarBlake2b;
// we might want to swap this one with a different implementation
use chacha::ChaCha;
use lioness::{Lioness, RAW_KEY_SIZE};

use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, MAXIMUM_PLAINTEXT_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER,
};
use crate::header::keys::PayloadKey;
use crate::route::DestinationAddressBytes;
use crate::ProcessingError;

// we might want to swap this one with a different implementation
#[derive(Clone)]
pub struct Payload {
    // We may be able to switch from Vec to array types as an optimization,
    // as in theory everything will have a constant size which we already know.
    // For now we'll stick with Vectors.
    content: Vec<u8>,
}

#[derive(Debug)]
pub enum PayloadEncapsulationError {
    TooLongPlaintextError,
}

impl Payload {
    pub fn encapsulate_message(
        plaintext_message: &[u8],
        payload_keys: &[PayloadKey],
        destination_address: DestinationAddressBytes,
    ) -> Result<Self, PayloadEncapsulationError> {
        let final_payload_key = payload_keys
            .last()
            .expect("The keys should be already initialized");
        // encapsulate_most_inner_payload
        let final_payload_layer =
            Self::encrypt_final_layer(plaintext_message, final_payload_key, destination_address)?;

        Ok(Self::encrypt_outer_layers(
            final_payload_layer,
            payload_keys,
        ))
    }

    // this is expected to get called after unwrapping all layers so it should be fine to get ownership of the content
    // as the payload object should no longer be used
    pub fn get_content(self) -> Vec<u8> {
        self.content
    }

    pub fn get_content_ref(&self) -> &[u8] {
        self.content.as_ref()
    }

    // in this context final means most inner layer
    fn encrypt_final_layer(
        message: &[u8],
        final_payload_key: &PayloadKey,
        destination_address: DestinationAddressBytes,
    ) -> Result<Self, PayloadEncapsulationError> {
        if message.len() > MAXIMUM_PLAINTEXT_LENGTH {
            return Err(PayloadEncapsulationError::TooLongPlaintextError);
        }
        // concatenate security zero padding with destination and message and additional length padding
        let mut final_payload: Vec<u8> = std::iter::repeat(0u8)
            .take(SECURITY_PARAMETER) // start with zero-padding
            .chain(destination_address.to_vec().iter().cloned())
            .chain(message.iter().cloned())
            .chain(std::iter::repeat(1u8).take(1)) // add single 1 byte to indicate start of padding
            .chain(std::iter::repeat(0u8)) // and fill everything else with zeroes
            .take(PAYLOAD_SIZE) // take however much we need (remember, iterators are lazy)
            .collect();

        // encrypt the padded plaintext using the payload key
        let lioness_cipher =
            Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(final_payload_key, 0, RAW_KEY_SIZE));
        lioness_cipher.encrypt(&mut final_payload).unwrap();

        Ok(Payload {
            content: final_payload,
        })
    }

    fn encrypt_outer_layers(final_payload_layer: Self, route_payload_keys: &[PayloadKey]) -> Self {
        route_payload_keys
            .iter()
            .take(route_payload_keys.len() - 1) // don't take the last key as it was used in create_final_encrypted_payload
            .rev()
            .fold(
                final_payload_layer,
                |previous_payload_layer, payload_key| {
                    Self::add_layer_of_encryption(previous_payload_layer, payload_key)
                },
            )
    }

    fn add_layer_of_encryption(current_layer: Self, payload_enc_key: &PayloadKey) -> Self {
        let lioness_cipher =
            Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(payload_enc_key, 0, RAW_KEY_SIZE));

        let mut payload_content = current_layer.content;
        lioness_cipher.encrypt(&mut payload_content).unwrap();

        Payload {
            content: payload_content,
        }
    }

    pub fn unwrap(self, payload_key: &PayloadKey) -> Self {
        let mut payload_content = self.content;
        let lioness_cipher =
            Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(payload_key, 0, RAW_KEY_SIZE));
        lioness_cipher.decrypt(&mut payload_content).unwrap();
        Payload {
            content: payload_content,
        }
    }

    pub fn try_recover_destination_and_plaintext(
        self,
    ) -> Option<(DestinationAddressBytes, Vec<u8>)> {
        // assuming our payload is fully decrypted it has the structure of:
        // 00000.... (SECURITY_PARAMETER length)
        // ADDRESS (DESTINATION_ADDRESS_LENGTH length)
        // plaintext (variable)
        // 1 (single 1 byte)
        // 0000 ... to pad to PAYLOAD_SIZE

        // so we need to ignore first SECURITY_PARAMETER bytes
        // then parse next DESTINATION_ADDRESS_LENGTH bytes as destination address
        // from the remaining remove all tailing zeroes until first 1
        // and finally remove the first 1
        let (padded_destination, padded_plaintext) = self
            .content
            .split_at(SECURITY_PARAMETER + DESTINATION_ADDRESS_LENGTH);

        let mut destination_address: DestinationAddressBytes = [0u8; DESTINATION_ADDRESS_LENGTH];
        destination_address.copy_from_slice(&padded_destination[SECURITY_PARAMETER..]);

        // we are looking for first occurrence of 1 in the tail and we get its index
        if let Some(i) = padded_plaintext.iter().rposition(|b| *b == 1) {
            // and now we only take bytes until that point (but not including it)
            let plaintext = padded_plaintext.iter().cloned().take(i).collect();
            return Some((destination_address, plaintext));
        }

        // our plaintext is invalid
        None
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProcessingError> {
        if bytes.len() != PAYLOAD_SIZE {
            return Err(ProcessingError::InvalidPayloadLengthError);
        }

        Ok(Payload { content: bytes })
    }
}

#[cfg(test)]
mod building_payload_from_bytes {
    use super::*;

    #[test]
    fn from_bytes_returns_error_if_bytes_are_too_short() {
        let bytes = [0u8; 1].to_vec();
        let expected = ProcessingError::InvalidPayloadLengthError;
        match Payload::from_bytes(bytes) {
            Err(err) => assert_eq!(expected, err),
            _ => panic!("Should have returned an error when packet bytes too short"),
        };
    }

    #[test]
    fn from_bytes_panics_if_bytes_are_too_long() {
        let bytes = [0u8; 6666].to_vec();
        let expected = ProcessingError::InvalidPayloadLengthError;
        match Payload::from_bytes(bytes) {
            Err(err) => assert_eq!(expected, err),
            _ => panic!("Should have returned an error when packet bytes too long"),
        };
    }
}

#[cfg(test)]
mod test_encrypting_final_payload {
    use crate::header::keys::routing_keys_fixture;
    use crate::route::destination_address_fixture;

    use super::*;

    #[test]
    fn it_returns_encrypted_payload_of_expected_payload_size() {
        let message = vec![1u8, 16];
        let destination = destination_address_fixture();
        let routing_keys = routing_keys_fixture();
        let final_enc_payload =
            Payload::encrypt_final_layer(&message, &routing_keys.payload_key, destination).unwrap();

        assert_eq!(PAYLOAD_SIZE, final_enc_payload.content.len());
    }
}

#[cfg(test)]
mod test_encapsulating_payload {
    use crate::constants::PAYLOAD_KEY_SIZE;
    use crate::route::destination_address_fixture;

    use super::*;

    #[test]
    fn always_the_payload_is_of_the_same_expected_type() {
        let message = vec![1u8, 16];
        let destination = destination_address_fixture();
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = vec![payload_key_1, payload_key_2, payload_key_3];

        let final_enc_payload =
            Payload::encrypt_final_layer(&message, &payload_key_1, destination).unwrap();
        let payload_encapsulation = Payload::encrypt_outer_layers(final_enc_payload, &payload_keys);
        assert_eq!(PAYLOAD_SIZE, payload_encapsulation.content.len());
    }
}

#[cfg(test)]
mod test_unwrapping_payload {
    use crate::constants::{PAYLOAD_KEY_SIZE, SECURITY_PARAMETER};
    use crate::route::destination_address_fixture;

    use super::*;

    #[test]
    fn unwrapping_results_in_original_payload_plaintext() {
        let message = vec![42u8; 16];
        let destination = destination_address_fixture();
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, destination).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key)
            });

        let zero_bytes = vec![0u8; SECURITY_PARAMETER];
        let additional_padding =
            vec![0u8; PAYLOAD_SIZE - SECURITY_PARAMETER - message.len() - destination.len() - 1];
        let expected_payload = [
            zero_bytes,
            destination.to_vec(),
            message,
            vec![1],
            additional_padding,
        ]
        .concat();
        assert_eq!(expected_payload, unwrapped_payload.get_content());
    }
}

#[cfg(test)]
mod plaintext_recovery {
    use crate::constants::PAYLOAD_KEY_SIZE;

    use super::*;

    #[test]
    fn it_is_possible_to_recover_plaintext_from_valid_payload() {
        let message = vec![42u8; 160];
        let destination = [11u8; DESTINATION_ADDRESS_LENGTH];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, destination).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key)
            });

        let (recovered_address, recovered_plaintext) = unwrapped_payload
            .try_recover_destination_and_plaintext()
            .unwrap();

        assert_eq!(destination, recovered_address);
        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_is_possible_to_recover_plaintext_even_if_is_just_ones() {
        let message = vec![1u8; 160];
        let destination = [11u8; DESTINATION_ADDRESS_LENGTH];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, destination).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key)
            });

        let (recovered_address, recovered_plaintext) = unwrapped_payload
            .try_recover_destination_and_plaintext()
            .unwrap();

        assert_eq!(destination, recovered_address);
        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_is_possible_to_recover_plaintext_even_if_is_just_zeroes() {
        let message = vec![0u8; 160];
        let destination = [11u8; DESTINATION_ADDRESS_LENGTH];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, destination).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key)
            });

        let (recovered_address, recovered_plaintext) = unwrapped_payload
            .try_recover_destination_and_plaintext()
            .unwrap();

        assert_eq!(destination, recovered_address);
        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_fails_to_recover_plaintext_from_invalid_payload() {
        let message = vec![42u8; 160];
        let destination = [11u8; DESTINATION_ADDRESS_LENGTH];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, destination).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .skip(1) // 'forget' about one key to obtain invalid decryption
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key)
            });

        let (recovered_address, recovered_plaintext) = unwrapped_payload
            .try_recover_destination_and_plaintext()
            .unwrap();

        assert_ne!(destination, recovered_address);
        assert_ne!(message, recovered_plaintext);
    }

    #[test]
    fn it_fails_to_recover_plaintext_from_incorrectly_constructed_payload() {
        let zero_payload = Payload {
            content: vec![0u8; PAYLOAD_SIZE],
        };
        assert_eq!(None, zero_payload.try_recover_destination_and_plaintext());
    }
}
