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

use crate::constants::SECURITY_PARAMETER;
use crate::header::keys::PayloadKey;
use crate::{Error, ErrorKind, Result};
use arrayref::array_ref;
use blake2::VarBlake2b;
use chacha::ChaCha; // we might want to swap this one with a different implementation
use lioness::Lioness;

// payload consists of security parameter long zero-padding, plaintext and '1' byte to indicate start of padding
// (it can optionally be followed by zero-padding
pub const PAYLOAD_OVERHEAD_SIZE: usize = SECURITY_PARAMETER + 1;

// TODO: question: is padding to some pre-defined length a sphinx-specific thing or rather
// something for our particular use case?
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Payload(Vec<u8>);

// is_empty does not make sense in this context, as you can't construct an empty Payload
#[allow(clippy::len_without_is_empty)]
impl Payload {
    /// Tries to encapsulate provided plaintext message inside a sphinx payload adding
    /// as many layers of encryption as there are keys provided.
    /// Note that the encryption layers are going to be added in *reverse* order!
    pub fn encapsulate_message(
        plaintext_message: &[u8],
        payload_keys: &[PayloadKey],
        payload_size: usize,
    ) -> Result<Self> {
        Self::validate_parameters(payload_size, plaintext_message.len())?;
        let mut payload = Self::set_final_payload(plaintext_message, payload_size);

        // remember that we need to reverse the order of encryption
        for payload_key in payload_keys.iter().rev() {
            payload = payload.add_encryption_layer(payload_key)?;
        }

        Ok(payload)
    }

    /// Ensures the desires payload_size is longer than the required overhead as well
    /// as the blocksize of lioness encryption.
    /// It also checks if the plaintext can fit in the specified payload [size].
    fn validate_parameters(payload_size: usize, plaintext_len: usize) -> Result<()> {
        if payload_size < PAYLOAD_OVERHEAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "specified payload_size is smaller than the required overhead",
            ));
        // lioness blocksize is 32 bytes (in this implementation)
        // Technically this check shouldn't happen if you're not going to add any
        // encryption layers to the payload, but then why are you even using sphinx?
        } else if payload_size < lioness::DIGEST_RESULT_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "specified payload_size is smaller lioness block size",
            ));
        }

        let maximum_plaintext_length = payload_size - PAYLOAD_OVERHEAD_SIZE;
        if plaintext_len > maximum_plaintext_length {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!(
                    "too long message provided. Message was: {}B long, maximum_plaintext_length is: {}B",
                    plaintext_len,
                    maximum_plaintext_length
                ),
            ));
        }
        Ok(())
    }

    /// Attaches leading and trailing paddings of correct lengths to the provided plaintext message.
    /// Note: this function should only ever be called in [`encapsulate_message`] after
    /// [`validate_parameters`] was performed.
    fn set_final_payload(plaintext_message: &[u8], payload_size: usize) -> Self {
        let final_payload: Vec<u8> = std::iter::repeat(0u8)
            .take(SECURITY_PARAMETER) // start with zero-padding
            .chain(plaintext_message.iter().cloned()) // put the plaintext
            .chain(std::iter::repeat(1u8).take(1)) // add single 1 byte to indicate start of padding
            .chain(std::iter::repeat(0u8)) // and fill everything else with zeroes
            .take(payload_size) // take however much we need (remember, iterators are lazy)
            .collect();

        Payload(final_payload)
    }

    /// Tries to add an additional layer of encryption onto self.
    fn add_encryption_layer(mut self, payload_enc_key: &PayloadKey) -> Result<Self> {
        let lioness_cipher = Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(
            payload_enc_key,
            0,
            lioness::RAW_KEY_SIZE
        ));

        if let Err(err) = lioness_cipher.encrypt(&mut self.0) {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("error while encrypting payload - {}", err),
            ));
        };
        Ok(self)
    }

    /// Tries to remove single layer of encryption from self.
    pub fn unwrap(mut self, payload_key: &PayloadKey) -> Result<Self> {
        let lioness_cipher = Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(
            payload_key,
            0,
            lioness::RAW_KEY_SIZE
        ));
        if let Err(err) = lioness_cipher.decrypt(&mut self.0) {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("error while unwrapping payload - {}", err),
            ));
        };
        Ok(self)
    }

    /// After calling [`unwrap`] required number of times with correct `payload_keys`, tries to parse
    /// the resultant payload content into original encapsulated plaintext message.
    pub fn recover_plaintext(self) -> Result<Vec<u8>> {
        debug_assert!(self.len() > PAYLOAD_OVERHEAD_SIZE);

        // assuming our payload is fully decrypted it has the following structure:
        // 00000.... (SECURITY_PARAMETER length)
        // plaintext (variable)
        // 1 (single 1 byte)
        // 0000 ... to pad to specified `payload_size`

        // In order to recover the plaintext we need to ignore first SECURITY_PARAMETER bytes
        // Then remove all tailing zeroes until first 1
        // and finally remove the first 1. The result should be our plaintext.
        // However, we must check if first SECURITY_PARAMETER bytes are actually 0
        if !self.0.iter().take(SECURITY_PARAMETER).all(|b| *b == 0) {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "malformed payload - no leading zero padding present",
            ));
        }

        // only trailing padding present
        let padded_plaintext = self
            .into_inner()
            .into_iter()
            .skip(SECURITY_PARAMETER)
            .collect::<Vec<_>>();

        // we are looking for first occurrence of 1 in the tail and we get its index
        if let Some(i) = padded_plaintext.iter().rposition(|b| *b == 1) {
            // and now we only take bytes until that point (but not including it)
            let plaintext = padded_plaintext.into_iter().take(i).collect();
            return Ok(plaintext);
        }

        // our plaintext is invalid
        Err(Error::new(
            ErrorKind::InvalidPayload,
            "malformed payload - invalid trailing padding",
        ))
    }

    fn into_inner(self) -> Vec<u8> {
        self.0
    }

    fn inner(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// View this `Payload` as slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner()
    }

    /// Convert this `Payload` as a vector of bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_inner()
    }

    /// Tries to recover `Payload` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // with payloads being dynamic in size, the only thing we can do
        // is to check if it at least is longer than the minimum length
        if bytes.len() < PAYLOAD_OVERHEAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "too short payload provided",
            ));
        }

        Ok(Payload(bytes.to_vec()))
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
mod parameter_verification {
    use super::*;

    #[test]
    fn it_returns_an_error_if_payload_size_is_smaller_than_the_overhead() {
        assert!(Payload::validate_parameters(PAYLOAD_OVERHEAD_SIZE - 1, 16).is_err());
    }

    #[test]
    fn it_returns_an_error_if_payload_size_is_smaller_than_the_lioness_blocklen() {
        assert!(Payload::validate_parameters(lioness::DIGEST_RESULT_SIZE - 1, 16).is_err());
    }

    #[test]
    fn it_returns_an_error_if_message_is_longer_than_maximum_allowed_length() {
        let payload_length = 100;
        let max_allowed_length = payload_length - PAYLOAD_OVERHEAD_SIZE;
        assert!(Payload::validate_parameters(payload_length, max_allowed_length + 1).is_err());
    }
}

#[cfg(test)]
mod final_payload_setting {
    use super::*;

    #[test]
    fn adds_correct_padding() {
        let plaintext_lengths = vec![0, 1, 16, 128, 4096];
        for plaintext_length in plaintext_lengths {
            // ensure payload always has correct length, because we're not testing for that
            let payload_size = plaintext_length + lioness::DIGEST_RESULT_SIZE;
            let final_payload =
                Payload::set_final_payload(&vec![42u8; plaintext_length], payload_size);
            let final_payload_inner = final_payload.into_inner();

            // first SECURITY_PARAMETER bytes have to be 0
            assert!(final_payload_inner
                .iter()
                .take(SECURITY_PARAMETER)
                .all(|&b| b == 0));
            // then the actual message should follow
            assert!(final_payload_inner
                .iter()
                .skip(SECURITY_PARAMETER)
                .take(plaintext_length)
                .all(|&b| b == 42));
            // single one
            assert_eq!(
                final_payload_inner[SECURITY_PARAMETER + plaintext_length],
                1
            );
            // and the rest should be 0 padding
            assert!(final_payload_inner
                .iter()
                .skip(SECURITY_PARAMETER + plaintext_length + 1)
                .all(|&b| b == 0))
        }
    }
}

#[cfg(test)]
mod test_encapsulating_payload {
    use super::*;
    use crate::constants::PAYLOAD_KEY_SIZE;

    #[test]
    fn can_be_encapsulated_without_encryption() {
        let message = vec![1u8, 16];
        let payload_size = 512;
        let unencrypted_message =
            Payload::encapsulate_message(&message, &[], payload_size).unwrap();

        // should be equivalent to just setting final payload
        assert_eq!(
            unencrypted_message,
            Payload::set_final_payload(&message, payload_size)
        )
    }

    #[test]
    fn works_with_single_encryption_layer() {
        let message = vec![1u8, 16];
        let payload_size = 512;
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];

        assert!(Payload::encapsulate_message(&message, &[payload_key_1], payload_size).is_ok())
    }

    #[test]
    fn works_with_five_encryption_layers() {
        let message = vec![1u8, 16];
        let payload_size = 512;
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_key_4 = [6u8; PAYLOAD_KEY_SIZE];
        let payload_key_5 = [7u8; PAYLOAD_KEY_SIZE];

        assert!(Payload::encapsulate_message(
            &message,
            &[
                payload_key_1,
                payload_key_2,
                payload_key_3,
                payload_key_4,
                payload_key_5
            ],
            payload_size
        )
        .is_ok())
    }
}

#[cfg(test)]
mod test_unwrapping_payload {
    use super::*;
    use crate::constants::{PAYLOAD_KEY_SIZE, SECURITY_PARAMETER};
    use crate::packet::builder::DEFAULT_PAYLOAD_SIZE;

    #[test]
    fn unwrapping_results_in_original_payload_plaintext() {
        let message = vec![42u8; 16];
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let zero_bytes = vec![0u8; SECURITY_PARAMETER];
        let additional_padding =
            vec![0u8; DEFAULT_PAYLOAD_SIZE - PAYLOAD_OVERHEAD_SIZE - message.len()];
        let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
        assert_eq!(expected_payload, unwrapped_payload.into_inner());
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

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let recovered_plaintext = unwrapped_payload.recover_plaintext().unwrap();

        assert_eq!(message, recovered_plaintext);
    }

    // tests for correct padding detection
    #[test]
    fn it_is_possible_to_recover_plaintext_even_if_is_just_ones() {
        let message = vec![1u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let recovered_plaintext = unwrapped_payload.recover_plaintext().unwrap();

        assert_eq!(message, recovered_plaintext);
    }

    // tests for correct padding detection
    #[test]
    fn it_is_possible_to_recover_plaintext_even_if_is_just_zeroes() {
        let message = vec![0u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        let recovered_plaintext = unwrapped_payload.recover_plaintext().unwrap();

        assert_eq!(message, recovered_plaintext);
    }

    #[test]
    fn it_fails_to_recover_plaintext_from_invalid_payload() {
        let message = vec![42u8; 160];

        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let encrypted_payload =
            Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE).unwrap();

        let unwrapped_payload = payload_keys
            .iter()
            .skip(1) // 'forget' about one key to obtain invalid decryption
            .fold(encrypted_payload, |current_layer, payload_key| {
                current_layer.unwrap(payload_key).unwrap()
            });

        assert!(unwrapped_payload.recover_plaintext().is_err())
    }

    #[test]
    fn it_fails_to_recover_plaintext_from_incorrectly_constructed_payload() {
        let zero_payload = Payload(vec![0u8; DEFAULT_PAYLOAD_SIZE]);

        assert!(zero_payload.recover_plaintext().is_err());
    }
}
