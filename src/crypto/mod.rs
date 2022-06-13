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

use aes::cipher::{KeyIvInit, StreamCipher};
use digest::generic_array::ArrayLength;
use digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::{crypto_mac, Hmac, Mac, NewMac};

pub mod keys;

// to not break existing imports
pub use keys::*;

pub const STREAM_CIPHER_KEY_SIZE: usize = 16;
pub const STREAM_CIPHER_INIT_VECTOR: [u8; 16] = [0u8; 16];

// Type alias for ease of use so that it would not require explicit import of crypto_mac or Hmac
pub type HmacOutput<D> = crypto_mac::Output<Hmac<D>>;

// Type alias for Aes128 ctr mode
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

pub fn generate_pseudorandom_bytes(
    // TODO: those should use proper generic arrays to begin with!!
    // ^ will be done in next PR
    key: &[u8; STREAM_CIPHER_KEY_SIZE],
    iv: &[u8; STREAM_CIPHER_KEY_SIZE],
    length: usize,
) -> Vec<u8> {
    // generate a random string as an output of a PRNG, which we implement using stream cipher AES_CTR
	let mut cipher = Aes128Ctr::new(key.into(), iv.into());
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

    // TODO: 10,000 is the wrong number, @aniap what is correct here?
    #[test]
    fn it_generates_output_of_size_10000() {
        let key: [u8; STREAM_CIPHER_KEY_SIZE] =
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let iv: [u8; STREAM_CIPHER_KEY_SIZE] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let rand_bytes = generate_pseudorandom_bytes(&key, &iv, 10000);
        assert_eq!(10000, rand_bytes.len());
    }
}
