use crate::header::header::RoutingKeys;
use crate::header::keys;
use crate::utils::crypto;
use crate::{constants, utils};

pub fn generate_pseudorandom_filler(routing_keys: &Vec<RoutingKeys>) -> Vec<u8> {
    routing_keys
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
        .fold(
            Vec::new(),
            |filler_string_accumulator, (i, pseudorandom_bytes)| {
                generate_filler(filler_string_accumulator, i, pseudorandom_bytes)
            },
        )
}

fn generate_filler(
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
        2 * i * constants::SECURITY_PARAMETER
    );

    let zero_bytes = vec![0u8; 2 * constants::SECURITY_PARAMETER];
    filler_string_accumulator.extend(&zero_bytes);

    // after computing the output vector of AES_CTR we take the last 2*k*i elements of the returned vector
    // and xor it with the current filler string
    utils::bytes::xor_with(
        &mut filler_string_accumulator,
        &pseudorandom_bytes
            [(2 * (constants::MAX_PATH_LENGTH - (i + 1)) + 3) * constants::SECURITY_PARAMETER..],
    );

    filler_string_accumulator
}

#[cfg(test)]
mod test_creating_pseudorandom_bytes {
    use super::*;

    #[test]
    fn with_no_keys_it_generates_empty_filler_string() {
        let routing_keys: Vec<RoutingKeys> = vec![];
        let filler_string = generate_pseudorandom_filler(&routing_keys);

        assert_eq!(0, filler_string.len());
    }

    #[test]
    fn with_1_key_it_generates_filler_of_length_1_times_2_times_security_parameter() {
        let shared_keys: Vec<crypto::SharedKey> = vec![crypto::generate_random_curve_point()];
        let routing_keys = &shared_keys
            .iter()
            .map(|&key| keys::key_derivation_function(key))
            .collect();
        let filler_string = generate_pseudorandom_filler(routing_keys);

        assert_eq!(2 * constants::SECURITY_PARAMETER, filler_string.len());
    }

    #[test]
    fn with_3_key_it_generates_filler_of_length_3_times_2_times_security_parameter() {
        let shared_keys: Vec<crypto::SharedKey> = vec![
            crypto::generate_random_curve_point(),
            crypto::generate_random_curve_point(),
            crypto::generate_random_curve_point(),
        ];
        let routing_keys = &shared_keys
            .iter()
            .map(|&key| keys::key_derivation_function(key))
            .collect();
        let filler_string = generate_pseudorandom_filler(routing_keys);
        assert_eq!(3 * 2 * constants::SECURITY_PARAMETER, filler_string.len());
    }

    #[test]
    #[should_panic]
    fn panics_with_more_keys_than_the_maximum_path_length() {
        let shared_keys: Vec<crypto::SharedKey> = std::iter::repeat(())
            .take(constants::MAX_PATH_LENGTH + 1)
            .map(|_| crypto::generate_random_curve_point())
            .collect();
        let routing_keys = &shared_keys
            .iter()
            .map(|&key| keys::key_derivation_function(key))
            .collect();
        generate_pseudorandom_filler(routing_keys);
    }
}

#[cfg(test)]
mod test_generating_filler_bytes {
    use super::*;

    mod for_valid_inputs {
        use super::*;

        #[test]
        fn it_returns_the_xored_byte_vector_of_a_correct_length() {
            let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let filler_string_accumulator = vec![0; 32];
            let filler_string = generate_filler(filler_string_accumulator, 1, pseudorandom_bytes);
            assert_eq!(64, filler_string.len());
            for x in filler_string {
                assert_eq!(0, x); // XOR of 0 + 0 == 0
            }
        }

        mod for_an_empty_filler_string_accumulator {
            use super::*;

            #[test]
            fn it_returns_a_byte_vector_of_length_2_times_security_parameter() {
                let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
                generate_filler(vec![], 0, pseudorandom_bytes);
            }
        }
    }

    mod for_invalid_inputs {
        use super::*;

        #[test]
        #[should_panic]
        fn panics_for_incorrectly_sized_pseudorandom_bytes_vector_and_accumulator_vector() {
            let pseudorandom_bytes = vec![0; 1];
            generate_filler(vec![], 0, pseudorandom_bytes);
        }

        #[test]
        #[should_panic]
        fn panics_with_incorrect_length_filler_accumulator() {
            let good_pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
            let wrong_accumulator = vec![0; 25];
            generate_filler(wrong_accumulator, 1, good_pseudorandom_bytes);
        }
    }
}
