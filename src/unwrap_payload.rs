use crate::header::keys::PayloadKey;
use arrayref::array_ref;
use blake2::VarBlake2b;
use chacha::ChaCha;
use lioness::{Lioness, RAW_KEY_SIZE};

pub fn unwrap_payload(enc_payload: Vec<u8>, payload_key: &PayloadKey) -> Vec<u8> {
    let mut new_payload = enc_payload;
    let lioness_cipher =
        Lioness::<VarBlake2b, ChaCha>::new_raw(array_ref!(payload_key, 0, RAW_KEY_SIZE));
    lioness_cipher.decrypt(&mut new_payload).unwrap();
    new_payload
}

#[cfg(test)]
mod test_unwrapping_payload {
    use super::*;
    use crate::constants::{PAYLOAD_KEY_SIZE, SECURITY_PARAMETER};
    use crate::payload::create;
    use crate::route::destination_address_fixture;

    #[test]
    fn unwraping_results_in_original_payload_plaintext() {
        let message = vec![1u8, 16];
        let destination = destination_address_fixture();
        let payload_key_1 = [3u8; PAYLOAD_KEY_SIZE];
        let payload_key_2 = [4u8; PAYLOAD_KEY_SIZE];
        let payload_key_3 = [5u8; PAYLOAD_KEY_SIZE];
        let payload_keys = [payload_key_1, payload_key_2, payload_key_3];

        let mut encrypted_payload = create(&message, payload_keys.to_vec(), destination);
        for key in payload_keys.iter() {
            encrypted_payload = unwrap_payload(encrypted_payload, key);
        }
        let zero_bytes = vec![0u8; SECURITY_PARAMETER];
        let expected_payload = [zero_bytes, destination.to_vec(), message].concat();
        assert_eq!(expected_payload, encrypted_payload);
    }
}
