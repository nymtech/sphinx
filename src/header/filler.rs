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

use crate::constants::{HEADER_INTEGRITY_MAC_SIZE, MAX_PATH_LENGTH, NODE_META_INFO_SIZE};
use crate::crypto;
use crate::header::keys::RoutingKeys;
use crate::{constants, utils};

pub const FILLER_STEP_SIZE_INCREASE: usize = NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE;

#[derive(Debug, PartialEq)]
pub struct Filler {
    value: Vec<u8>,
}

impl Filler {
    pub fn new(routing_keys: &[RoutingKeys]) -> Self {
        assert!(routing_keys.len() <= MAX_PATH_LENGTH);
        let filler_value = routing_keys
            .iter()
            .map(|node_routing_keys| node_routing_keys.stream_cipher_key) // we only want the cipher key
            .map(|cipher_key| {
				crypto::generate_pseudorandom_bytes(
					&cipher_key,
					&crypto::STREAM_CIPHER_INIT_VECTOR,
					constants::STREAM_CIPHER_OUTPUT_LENGTH,
				)
            }) // the actual cipher key is only used to generate the pseudorandom bytes
            .enumerate() // we need to know index of each element to take correct slice of the PRNG output
            .map(|(i, pseudorandom_bytes)| (i + 1, pseudorandom_bytes)) // the zeroth step is the empty filler and we add on top of it
            .fold(
                Vec::new(),
                |filler_string_accumulator, (i, pseudorandom_bytes)| {
                    Self::filler_step(filler_string_accumulator, i, pseudorandom_bytes)
                },
            );
        Self {
            value: filler_value,
        }
    }

    fn filler_step(
        mut filler_string_accumulator: Vec<u8>,
        i: usize,
        pseudorandom_bytes: Vec<u8>,
    ) -> Vec<u8> {
        assert_eq!(
            pseudorandom_bytes.len(),
            constants::STREAM_CIPHER_OUTPUT_LENGTH
        );
        assert_eq!(
            filler_string_accumulator.len(),
            FILLER_STEP_SIZE_INCREASE * (i - 1) // make sure it has length of the previous step
        );
        let zero_bytes = vec![0u8; FILLER_STEP_SIZE_INCREASE];
        filler_string_accumulator.extend(&zero_bytes);

        // after computing the output vector of AES_CTR we take the last 3*k*i elements of the returned vector
        // and xor it with the current filler string
        utils::bytes::xor_with(
            &mut filler_string_accumulator,
            &pseudorandom_bytes[pseudorandom_bytes.len() - i * FILLER_STEP_SIZE_INCREASE..],
        );

        filler_string_accumulator
    }

    pub fn get_value(self) -> Vec<u8> {
        self.value
    }

    pub(crate) fn from_raw(raw_value: Vec<u8>) -> Self {
        Filler { value: raw_value }
    }
}

#[cfg(test)]
mod test_creating_pseudorandom_bytes {
    use crate::header::keys;

    use super::*;
    use crypto::{EphemeralSecret, SharedSecret};

    #[test]
    fn with_no_keys_it_generates_empty_filler_string() {
        let routing_keys: Vec<RoutingKeys> = vec![];
        let filler_string = Filler::new(&routing_keys);

        assert_eq!(0, filler_string.value.len());
    }

    #[test]
    fn with_1_key_it_generates_filler_of_length_1_times_3_times_security_parameter() {
        let shared_keys = vec![SharedSecret::from(&EphemeralSecret::new())];
        let routing_keys: Vec<_> = shared_keys
            .iter()
            .map(|&key| keys::RoutingKeys::derive(key))
            .collect();
        let filler_string = Filler::new(&routing_keys);

        assert_eq!(FILLER_STEP_SIZE_INCREASE, filler_string.value.len());
    }

    #[test]
    fn with_3_key_it_generates_filler_of_length_3_times_3_times_security_parameter() {
        let shared_keys = vec![
            SharedSecret::from(&EphemeralSecret::new()),
            SharedSecret::from(&EphemeralSecret::new()),
            SharedSecret::from(&EphemeralSecret::new()),
        ];
        let routing_keys: Vec<_> = shared_keys
            .iter()
            .map(|&key| keys::RoutingKeys::derive(key))
            .collect();
        let filler_string = Filler::new(&routing_keys);
        assert_eq!(3 * FILLER_STEP_SIZE_INCREASE, filler_string.value.len());
    }

    #[test]
    #[should_panic]
    fn panics_with_more_keys_than_the_maximum_path_length() {
        let shared_keys: Vec<_> = std::iter::repeat(())
            .take(constants::MAX_PATH_LENGTH + 1)
            .map(|_| SharedSecret::from(&EphemeralSecret::new()))
            .collect();
        let routing_keys: Vec<_> = shared_keys
            .iter()
            .map(|&key| keys::RoutingKeys::derive(key))
            .collect();
        Filler::new(&routing_keys);
    }
}

#[cfg(test)]
mod test_new_filler_bytes {
    use super::*;
    use crate::test_utils::fixtures::routing_keys_fixture;

    #[test]
    fn it_retusn_filler_bytes_of_correct_length_for_3_routing_keys() {
        let routing_key_1 = routing_keys_fixture();
        let routing_key_2 = routing_keys_fixture();
        let routing_key_3 = routing_keys_fixture();
        let routing_keys = [routing_key_1, routing_key_2, routing_key_3];
        let filler = Filler::new(&routing_keys);
        assert_eq!(
            FILLER_STEP_SIZE_INCREASE * (routing_keys.len()),
            filler.get_value().len()
        )
    }

    #[test]
    fn it_retusn_filler_bytes_of_correct_length_for_4_routing_keys() {
        let routing_key_1 = routing_keys_fixture();
        let routing_key_2 = routing_keys_fixture();
        let routing_key_3 = routing_keys_fixture();
        let routing_key_4 = routing_keys_fixture();
        let routing_keys = [routing_key_1, routing_key_2, routing_key_3, routing_key_4];
        let filler = Filler::new(&routing_keys);
        assert_eq!(
            FILLER_STEP_SIZE_INCREASE * (routing_keys.len()),
            filler.get_value().len()
        )
    }
}

#[cfg(test)]
mod test_generating_filler_bytes {
    use super::*;

    mod for_valid_inputs {
        use super::*;

        #[test]
        fn it_returns_the_xored_byte_vector_of_a_correct_length_for_i_1() {
            let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let filler_string_accumulator = vec![];
            let filler_string =
                Filler::filler_step(filler_string_accumulator, 1, pseudorandom_bytes);
            assert_eq!(FILLER_STEP_SIZE_INCREASE, filler_string.len());
            for x in filler_string {
                assert_eq!(0, x); // XOR of 0 + 0 == 0
            }
        }

        #[test]
        fn it_returns_the_xored_byte_vector_of_a_correct_length_for_i_3() {
            let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let filler_string_accumulator = vec![0u8; 2 * FILLER_STEP_SIZE_INCREASE];
            let filler_string =
                Filler::filler_step(filler_string_accumulator, 3, pseudorandom_bytes);
            assert_eq!(FILLER_STEP_SIZE_INCREASE * 3, filler_string.len());
            for x in filler_string {
                assert_eq!(0, x); // XOR of 0 + 0 == 0
            }
        }

        mod for_an_empty_filler_string_accumulator {
            use super::*;

            #[test]
            #[should_panic]
            fn it_panics() {
                let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
                Filler::filler_step(vec![], 0, pseudorandom_bytes);
            }
        }
    }

    mod for_invalid_inputs {
        use super::*;

        #[test]
        #[should_panic]
        fn panics_for_incorrectly_sized_pseudorandom_bytes_vector_and_accumulator_vector() {
            let pseudorandom_bytes = vec![0; 1];
            Filler::filler_step(vec![], 0, pseudorandom_bytes);
        }

        #[test]
        #[should_panic]
        fn panics_with_incorrect_length_filler_accumulator() {
            let good_pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let wrong_accumulator = vec![0; 25];
            Filler::filler_step(wrong_accumulator, 1, good_pseudorandom_bytes);
        }
    }
}
