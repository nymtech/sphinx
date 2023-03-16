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

use aes::cipher::{NewCipher, StreamCipher};
use aes::Aes128Ctr;
use digest::generic_array::{ArrayLength, GenericArray};
use digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::{crypto_mac, Hmac, Mac, NewMac};

pub mod keys;

// to not break existing imports
pub use keys::*;

pub const STREAM_CIPHER_KEY_SIZE: usize = 16;
pub const STREAM_CIPHER_INIT_VECTOR: [u8; 16] = [0u8; 16];

// Type alias for ease of use so that it would not require explicit import of crypto_mac or Hmac
pub type HmacOutput<D> = crypto_mac::Output<Hmac<D>>;

pub fn generate_pseudorandom_bytes(
    // TODO: those should use proper generic arrays to begin with!!
    // ^ will be done in next PR
    key: &[u8; STREAM_CIPHER_KEY_SIZE],
    iv: &[u8; STREAM_CIPHER_KEY_SIZE],
    length: usize,
) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(&key[..]);
    let cipher_nonce = GenericArray::from_slice(&iv[..]);

    // generate a random string as an output of a PRNG, which we implement using stream cipher AES_CTR
    let mut cipher = Aes128Ctr::new(cipher_key, cipher_nonce);
    let mut data = vec![0u8; length];
    cipher.apply_keystream(&mut data);
    data
}

/// Compute keyed hmac
pub fn compute_keyed_hmac<D>(key: &[u8], data: &[u8]) -> HmacOutput<D>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    let mut hmac =
        Hmac::<D>::new_from_slice(key).expect("HMAC should be able to take key of any size!");
    hmac.update(data);
    hmac.finalize()
}

#[cfg(test)]
mod generating_pseudorandom_bytes {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn it_generates_data_as_expected_by_aes128ctr() {
        // using test vectors from: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .unwrap()
            .try_into()
            .unwrap();
        let expected_output = hex::decode("ec8cdf7398607cb0f2d21675ea9ea1e4").unwrap();

        assert_eq!(expected_output, generate_pseudorandom_bytes(&key, &iv, 16))
    }
}
