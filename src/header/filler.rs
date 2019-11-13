#[cfg(test)]
use speculate::speculate;

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
speculate! {
    describe "creating pseudorandom bytes" {
        context "for no keys" {
            it "generates empty filler string" {
                let routing_keys: Vec<RoutingKeys> = vec![];
                let filler_string = generate_pseudorandom_filler(&routing_keys);

                assert_eq!(0, filler_string.len());
            }
        }

        context "for one key" {
            it "generates filler string of length 1 * 2 * SECURITY_PARAMETER" {
                let shared_keys: Vec<crypto::SharedKey> = vec![crypto::generate_random_curve_point()];
                let routing_keys = &shared_keys.iter().map(|&key| keys::key_derivation_function(key)).collect();
                let filler_string = generate_pseudorandom_filler(routing_keys);

                assert_eq!(2 * constants::SECURITY_PARAMETER, filler_string.len());
            }
        }

        context "for three keys" {
            before {
                let shared_keys: Vec<crypto::SharedKey> = vec![
                crypto::generate_random_curve_point(),
                crypto::generate_random_curve_point(),
                crypto::generate_random_curve_point()
                ];
                let routing_keys = &shared_keys.iter().map(|&key| keys::key_derivation_function(key)).collect();
                let filler_string = generate_pseudorandom_filler(routing_keys);
            }
            it "generates filler string of length 3 * 2 * SECURITY_PARAMETER" {
                assert_eq!(3 * 2 * constants::SECURITY_PARAMETER, filler_string.len());
            }
        }

        context "more keys than the maximum path length" {
            #[should_panic]
            it "panics" {
                let shared_keys: Vec<crypto::SharedKey> = std::iter::repeat(())
                .take(constants::MAX_PATH_LENGTH + 1)
                .map(|_| crypto::generate_random_curve_point())
                .collect();
                let routing_keys = &shared_keys.iter().map(|&key| keys::key_derivation_function(key)).collect();
                generate_pseudorandom_filler(routing_keys);
            }
        }

        describe "generating filler bytes" {
            context "for incorrectly sized pseudorandom bytes vector and accumulator vector"{
                #[should_panic]
                it "panics" {
                    let pseudorandom_bytes = vec![0; 1];
                    generate_filler(vec![], 0, pseudorandom_bytes);
                }
                context "when the filler accumulator is not the correct length" {
                    #[should_panic]
                    it "panics" {
                        let good_pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
                        let wrong_accumulator = vec![0; 25];
                        generate_filler(wrong_accumulator, 1, good_pseudorandom_bytes);
                    }

                }
            }
            context "for an empty filler string accumulator"{
                it "returns a byte vector of length 2 * SECURITY_PARAMETER" {
                    let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
                    generate_filler(vec![], 0, pseudorandom_bytes);
                }
            }

            context "for valid inputs"{
                it "returns the xored byte vector of a correct length"{
                    let pseudorandom_bytes = vec![0; constants::STREAM_CIPHER_OUTPUT_LENGTH];
                    let filler_string_accumulator = vec![0; 32];
                    let filler_string = generate_filler(filler_string_accumulator, 1, pseudorandom_bytes);
                    assert_eq!(64, filler_string.len());
                    for x in filler_string {
                    assert_eq!(0, x); // XOR of 0 + 0 == 0
                }
            }
        }
        }
    }
}
