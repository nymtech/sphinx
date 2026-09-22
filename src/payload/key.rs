// Copyright 2025 Nym Technologies SA
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

use crate::constants::{
    PAYLOAD_KEY_HKDF_INFO, PAYLOAD_KEY_HKDF_SALT, PAYLOAD_KEY_SEED_SIZE, PAYLOAD_KEY_SIZE,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::borrow::Borrow;

pub type PayloadKey = [u8; PAYLOAD_KEY_SIZE];
pub type PayloadKeySeed = [u8; PAYLOAD_KEY_SEED_SIZE];

// HKDF-SHA256 can expand to at most 255 * 32 bytes; the `expect` below relies on this.
const _: () = assert!(PAYLOAD_KEY_SIZE <= 255 * 32);

pub fn derive_payload_key(seed: &[u8; PAYLOAD_KEY_SEED_SIZE]) -> PayloadKey {
    let hkdf = Hkdf::<Sha256>::new(Some(PAYLOAD_KEY_HKDF_SALT), seed);

    let mut output = [0u8; PAYLOAD_KEY_SIZE];

    #[allow(clippy::expect_used)]
    hkdf.expand(PAYLOAD_KEY_HKDF_INFO, &mut output)
        .expect("PAYLOAD_KEY_SIZE is within HKDF-SHA256's output limit (const-asserted above)");

    output
}

// helper trait to allow us to use either PayloadKey (as reference) directly or the seed (to create owned key)
pub trait SphinxPayloadKey<'a> {
    type Key: Borrow<PayloadKey>;

    fn payload_key(&'a self) -> Self::Key;
}

impl<'a> SphinxPayloadKey<'a> for &'a PayloadKey {
    type Key = &'a PayloadKey;

    fn payload_key(&self) -> Self::Key {
        self
    }
}

impl<'a> SphinxPayloadKey<'a> for PayloadKey {
    type Key = &'a PayloadKey;

    fn payload_key(&'a self) -> Self::Key {
        self
    }
}

impl SphinxPayloadKey<'_> for &PayloadKeySeed {
    type Key = PayloadKey;

    fn payload_key(&self) -> Self::Key {
        derive_payload_key(self)
    }
}

impl SphinxPayloadKey<'_> for PayloadKeySeed {
    type Key = PayloadKey;

    fn payload_key(&self) -> Self::Key {
        derive_payload_key(self)
    }
}
