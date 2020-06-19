// Copyright 2020 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::constants::{DESTINATION_ADDRESS_LENGTH, SECURITY_PARAMETER};
use crate::header::keys::PayloadKey;
use crate::route::DestinationAddressBytes;
use crate::{Error, ErrorKind, Result};
use arrayref::array_ref;
use blake2::VarBlake2b;
use chacha::ChaCha; // we might want to swap this one with a different implementation
use lioness::{Lioness, RAW_KEY_SIZE};

// payload consists of security parameter long zero-padding, destination address, plaintext and '1' byte to indicate start of padding
// (it can optionally be followed by zero-padding
pub const PAYLOAD_OVERHEAD_SIZE: usize = SECURITY_PARAMETER + DESTINATION_ADDRESS_LENGTH + 1;

// we might want to swap this one with a different implementation
#[derive(Clone)]
pub struct Payload {
    // We may be able to switch from Vec to array types as an optimization,
    // as in theory everything will have a constant size which we already know.
    // For now we'll stick with Vectors.
    content: Vec<u8>,
}

// is_empty does not make sense in this context, as you can't construct an empty Payload
#[allow(clippy::len_without_is_empty)]
impl Payload {
    pub fn encapsulate_message(
        plaintext_message: &[u8],
        payload_keys: &[PayloadKey],
        destination_address: DestinationAddressBytes,
        payload_size: usize,
    ) -> Result<Self> {
        let final_payload_key = payload_keys
            .last()
            .expect("The keys should be already initialized");
        // encapsulate_most_inner_payload
        let final_payload_layer = Self::encrypt_final_layer(
            plaintext_message,
            final_payload_key,
            destination_address,
            payload_size,
        )?;

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

    pub fn len(&self) -> usize {
        self.content.len()
    }

    // in this context final means most inner layer
    fn encrypt_final_layer(
        message: &[u8],
        final_payload_key: &PayloadKey,
        destination_address: DestinationAddressBytes,
        payload_size: usize,
    ) -> Result<Self> {
        if payload_size < PAYLOAD_OVERHEAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "specified payload_size is smaller than the required overhead",
            ));
        }

        let maximum_plaintext_length = payload_size - PAYLOAD_OVERHEAD_SIZE;
        if message.len() > maximum_plaintext_length {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!(
                    "too long message provided. Message was: {}B long, maximum_plaintext_length is: {}B",
                    message.len(),
                    maximum_plaintext_length
                ),
            ));
        }
        // concatenate security zero padding with destination and message and additional length padding
        let mut final_payload: Vec<u8> = std::iter::repeat(0u8)
            .take(SECURITY_PARAMETER) // start with zero-padding
            .chain(destination_address.to_bytes().iter().cloned())
            .chain(message.iter().cloned())
            .chain(std::iter::repeat(1u8).take(1)) // add single 1 byte to indicate start of padding
            .chain(std::iter::repeat(0u8)) // and fill everything else with zeroes
            .take(payload_size) // take however much we need (remember, iterators are lazy)
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
                    previous_payload_layer.add_layer_of_encryption(payload_key)
                },
            )
    }

    fn add_layer_of_encryption(mut self, payload_enc_key: &PayloadKey) -> Self {
        let lioness_cipher =
            Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(payload_enc_key, 0, RAW_KEY_SIZE));

        lioness_cipher.encrypt(&mut self.content).unwrap();
        self
    }

    pub fn unwrap(mut self, payload_key: &PayloadKey) -> Self {
        let lioness_cipher =
            Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(payload_key, 0, RAW_KEY_SIZE));
        lioness_cipher.decrypt(&mut self.content).unwrap();
        self
    }

    pub fn try_recover_destination_and_plaintext(
        self,
    ) -> Result<(DestinationAddressBytes, Vec<u8>)> {
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

        let mut destination_address = [0u8; DESTINATION_ADDRESS_LENGTH];
        destination_address.copy_from_slice(&padded_destination[SECURITY_PARAMETER..]);
        let destination_address = DestinationAddressBytes::from_bytes(destination_address);

        // we are looking for first occurrence of 1 in the tail and we get its index
        if let Some(i) = padded_plaintext.iter().rposition(|b| *b == 1) {
            // and now we only take bytes until that point (but not including it)
            let plaintext = padded_plaintext.iter().cloned().take(i).collect();
            return Ok((destination_address, plaintext));
        }

        // our plaintext is invalid
        Err(Error::new(ErrorKind::InvalidPayload, "malformed payload"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // with payloads being dynamic in size, the only thing we can do
        // is to check if it at least is longer than the minimum length
        if bytes.len() < PAYLOAD_OVERHEAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "too short payload provided",
            ));
        }

        Ok(Payload {
            content: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod building_payload_from_bytes {
    use super::*;

    #[test]
    fn from_bytes_returns_error_if_bytes_are_too_short() {
        let bytes = [0u8; 1].to_vec();
        let expected = ErrorKind::InvalidPayload;
        match Payload::from_bytes(&bytes) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when packet bytes too short"),
        };
    }
}

#[cfg(test)]
mod test_encrypting_final_payload {
    use super::*;
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE,
        test_utils::fixtures::{destination_address_fixture, routing_keys_fixture},
    };

    #[test]
    fn it_returns_encrypted_payload_of_expected_payload_size_for_default_payload_size() {
        let message = vec![1u8; 16];
        let destination = destination_address_fixture();
        let routing_keys = routing_keys_fixture();
        let final_enc_payload = Payload::encrypt_final_layer(
            &message,
            &routing_keys.payload_key,
            destination,
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();

        assert_eq!(DEFAULT_PAYLOAD_SIZE, final_enc_payload.content.len());
    }

    #[test]
    fn it_returns_an_error_if_payload_size_is_smaller_than_the_overhead() {
        let message = vec![1u8; 16];
        let destination = destination_address_fixture();
        let routing_keys = routing_keys_fixture();
        assert!(Payload::encrypt_final_layer(
            &message,
            &routing_keys.payload_key,
            destination,
            PAYLOAD_OVERHEAD_SIZE - 1
        )
        .is_err());
    }

    #[test]
    fn it_returns_an_error_if_message_is_longer_than_maximum_allowed_length() {
        let payload_length = 100;
        let max_allowed_length = payload_length - PAYLOAD_OVERHEAD_SIZE;
        let message = vec![1u8; max_allowed_length + 1];
        let destination = destination_address_fixture();
        let routing_keys = routing_keys_fixture();
        assert!(Payload::encrypt_final_layer(
            &message,
            &routing_keys.payload_key,
            destination,
            PAYLOAD_OVERHEAD_SIZE - 1
        )
        .is_err());
    }

    #[test]
    fn it_returns_encrypted_payload_of_expected_size_for_empty_message() {
        let message = Vec::new();
        let destination = destination_address_fixture();
        let routing_keys = routing_keys_fixture();
        let final_enc_payload = Payload::encrypt_final_layer(
            &message,
            &routing_keys.payload_key,
            destination,
            PAYLOAD_OVERHEAD_SIZE,
        )
        .unwrap();

        assert_eq!(PAYLOAD_OVERHEAD_SIZE, final_enc_payload.content.len());
    }
}

#[cfg(test)]
mod test_encapsulating_payload {
    use super::*;
    use crate::constants::PAYLOAD_KEY_SIZE;
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE, test_utils::fixtures::destination_address_fixture,
    };

    #[test]
    fn always_the_payload_is_of_the_same_expected_type() {
        let message = vec![1u8, 16];
        let destination = destination_address_fixture();
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = vec![payload_key_1, payload_key_2, payload_key_3];

        let final_enc_payload = Payload::encrypt_final_layer(
            &message,
            &payload_key_1,
            destination,
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();
        let payload_encapsulation =
            Payload::encrypt_outer_layers(final_enc_payload.clone(), &payload_keys);
        assert_eq!(final_enc_payload.len(), payload_encapsulation.len());
    }
}

#[cfg(test)]
mod test_unwrapping_payload {
    use super::*;
    use crate::constants::{PAYLOAD_KEY_SIZE, SECURITY_PARAMETER};
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE, test_utils::fixtures::destination_address_fixture,
    };

    #[test]
    fn unwrapping_results_in_original_payload_plaintext() {
        let message = vec![42u8; 16];
        let destination = destination_address_fixture();
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload = Payload::encapsulate_message(
            &message,
            &payload_keys,
            destination.clone(),
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key)
            });

        let zero_bytes = vec![0u8; SECURITY_PARAMETER];
        let additional_padding =
            vec![0u8; DEFAULT_PAYLOAD_SIZE - PAYLOAD_OVERHEAD_SIZE - message.len()];
        let expected_payload = [
            zero_bytes,
            destination.to_bytes().to_vec(),
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
    use super::*;
    use crate::constants::PAYLOAD_KEY_SIZE;
    use crate::packet::builder::DEFAULT_PAYLOAD_SIZE;

    #[test]
    fn it_is_possible_to_recover_plaintext_from_valid_payload() {
        let message = vec![42u8; 160];
        let destination = DestinationAddressBytes::from_bytes([11u8; DESTINATION_ADDRESS_LENGTH]);

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload = Payload::encapsulate_message(
            &message,
            &payload_keys,
            destination.clone(),
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();

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
        let destination = DestinationAddressBytes::from_bytes([11u8; DESTINATION_ADDRESS_LENGTH]);

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload = Payload::encapsulate_message(
            &message,
            &payload_keys,
            destination.clone(),
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();

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
        let destination = DestinationAddressBytes::from_bytes([11u8; DESTINATION_ADDRESS_LENGTH]);

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload = Payload::encapsulate_message(
            &message,
            &payload_keys,
            destination.clone(),
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();

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
        let destination = DestinationAddressBytes::from_bytes([11u8; DESTINATION_ADDRESS_LENGTH]);

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload = Payload::encapsulate_message(
            &message,
            &payload_keys,
            destination.clone(),
            DEFAULT_PAYLOAD_SIZE,
        )
        .unwrap();

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
            content: vec![0u8; DEFAULT_PAYLOAD_SIZE],
        };
        assert!(zero_payload
            .try_recover_destination_and_plaintext()
            .is_err());
    }
}
