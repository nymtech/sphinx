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

use crate::constants::{
    HeaderIntegrityHmacAlgorithm, HeaderIntegrityMacSize, HEADER_INTEGRITY_MAC_SIZE,
};
use crate::crypto;
use crate::header::keys::HeaderIntegrityMacKey;
use digest::generic_array::GenericArray;
use subtle::{Choice, ConstantTimeEq};

// In paper gamma
#[derive(Clone, Debug)]
pub struct HeaderIntegrityMac(GenericArray<u8, HeaderIntegrityMacSize>);

impl HeaderIntegrityMac {
    pub(crate) fn compute(key: HeaderIntegrityMacKey, header_data: &[u8]) -> Self {
        let routing_info_mac =
            crypto::compute_keyed_hmac::<HeaderIntegrityHmacAlgorithm>(&key, &header_data);

        // NOTE: BE EXTREMELY CAREFUL HOW YOU MANAGE THOSE BYTES
        // YOU CAN'T TREAT THEM AS NORMAL ONES
        let mac_bytes = routing_info_mac.into_bytes();
        if mac_bytes.len() < HEADER_INTEGRITY_MAC_SIZE {
            panic!("Algorithm used for computing header integrity mac produced output smaller than minimum length of {}", HEADER_INTEGRITY_MAC_SIZE)
        }

        // only take first HEADER_INTEGRITY_MAC_SIZE bytes
        Self(
            mac_bytes
                .into_iter()
                .take(HEADER_INTEGRITY_MAC_SIZE)
                .collect(),
        )
    }

    pub fn verify(
        &self,
        integrity_mac_key: HeaderIntegrityMacKey,
        enc_routing_info: &[u8],
    ) -> bool {
        let recomputed_integrity_mac = Self::compute(integrity_mac_key, enc_routing_info);
        self.ct_eq(&recomputed_integrity_mac).into()
    }

    pub fn into_inner(self) -> GenericArray<u8, HeaderIntegrityMacSize> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; HEADER_INTEGRITY_MAC_SIZE]) -> Self {
        Self(bytes.into())
    }
}

impl ConstantTimeEq for HeaderIntegrityMac {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
mod computing_integrity_mac {
    use super::*;
    use crate::constants::INTEGRITY_MAC_KEY_SIZE;
    use crate::header::routing::ENCRYPTED_ROUTING_INFO_SIZE;

    #[test]
    fn it_is_possible_to_verify_correct_mac() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);

        assert!(integrity_mac.verify(key, &data));
    }

    #[test]
    fn it_lets_detecting_flipped_data_bits() {
        let key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let mut data = vec![3u8; ENCRYPTED_ROUTING_INFO_SIZE];
        let integrity_mac = HeaderIntegrityMac::compute(key, &data);
        data[10] = !data[10];
        assert!(!integrity_mac.verify(key, &data));
    }
}
