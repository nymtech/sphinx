use crate::constants::{DESTINATION_ADDRESS_LENGTH, SECURITY_PARAMETER};
use crate::header::header::Destination;
use crate::header::keys::PayloadKey;
use arrayref::array_ref;
use blake2::VarBlake2b; // we might want to swap this one with a different implementation
use chacha::ChaCha;
use lioness::{Lioness, RAW_KEY_SIZE}; // we might want to swap this one with a different implementation

// We may be able to switch from Vec to array types as an optimization,
// as in theory everything will have a constant size which we already know.
// For now we'll stick with Vecs.
pub fn create(
    payload: Vec<u8>,
    payload_keys: Vec<PayloadKey>,
    destination: &Destination,
) -> Vec<u8> {
    let final_payload_key = payload_keys
        .last()
        .expect("The keys should be already initialized");
    // encapsulate_most_inner_payload
    let encrypted_final_payload =
        create_final_encrypted_payload(payload, destination.address, final_payload_key);
    // encapsulate the rest
    encapsulate_payload(encrypted_final_payload, &payload_keys)
}

// final means most inner
fn create_final_encrypted_payload(
    message: Vec<u8>,
    destination_addr: [u8; 32],
    final_payload_key: &PayloadKey,
) -> Vec<u8> {
    // generate zero-padding
    let zero_bytes = vec![0u8; SECURITY_PARAMETER];
    // concatenate zero padding with destination and message
    let mut final_payload = [zero_bytes, destination_addr.to_vec(), message].concat();

    // encrypte the padded plaintext using the payload key
    let lioness_cipher =
        Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(final_payload_key, 0, RAW_KEY_SIZE));
    lioness_cipher.encrypt(&mut final_payload).unwrap();

    final_payload
}

fn encapsulate_payload(
    final_layer_payload_component: Vec<u8>,
    route_payload_keys: &[PayloadKey],
) -> Vec<u8> {
    let mut prev_payload_layer = final_layer_payload_component;
    for i in (0..route_payload_keys.len() - 1).rev() {
        let lioness_cipher = Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(
            route_payload_keys[i],
            0,
            RAW_KEY_SIZE
        ));
        lioness_cipher.encrypt(&mut prev_payload_layer).unwrap();
    }
    prev_payload_layer
}

#[cfg(test)]
mod test_encrypting_final_payload {
    use super::*;
    use crate::header::header::destination_address_fixture;
    use crate::header::routing::routing_keys_fixture;
    #[test]
    fn it_returns_the_same_length_encrypted_payload_as_plaintext_payload() {
        let message = vec![1u8, 16];
        let message_len = message.len();
        let destination = destination_address_fixture();
        let routing_keys = routing_keys_fixture();
        let final_enc_payload =
            create_final_encrypted_payload(message, destination, &routing_keys.payload_key);

        assert_eq!(
            SECURITY_PARAMETER + DESTINATION_ADDRESS_LENGTH + message_len,
            final_enc_payload.len()
        );
    }
}

#[cfg(test)]
mod test_encapsulating_payload {
    use super::*;
    use crate::constants::{INTEGRITY_MAC_KEY_SIZE, PAYLOAD_KEY_SIZE};
    use crate::header::header::destination_address_fixture;
    use crate::header::keys::RoutingKeys;
    use crate::header::routing::routing_keys_fixture;
    use crate::utils::crypto;
    #[test]
    fn always_both_input_and_output_are_the_same_length() {
        let message = vec![1u8, 16];
        let message_len = message.len();
        let destination = destination_address_fixture();
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = vec![payload_key_1, payload_key_2, payload_key_3];

        let final_enc_payload =
            create_final_encrypted_payload(message, destination, &payload_key_1);

        let payload_encapsulation = encapsulate_payload(final_enc_payload, &payload_keys);
        assert_eq!(
            SECURITY_PARAMETER + DESTINATION_ADDRESS_LENGTH + message_len,
            payload_encapsulation.len()
        );
    }
}
