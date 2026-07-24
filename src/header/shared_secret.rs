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
    BLINDING_FACTOR_SIZE, EXPANDED_SHARED_SECRET_HKDF_INFO, EXPANDED_SHARED_SECRET_HKDF_SALT,
    EXPANDED_SHARED_SECRET_LENGTH, INTEGRITY_MAC_KEY_SIZE, PAYLOAD_KEY_SEED_SIZE, PAYLOAD_KEY_SIZE,
    REPLAY_TAG_SIZE,
};
use crate::crypto::STREAM_CIPHER_KEY_SIZE;
use crate::header::keys::{HeaderIntegrityMacKey, StreamCipherKey};
use crate::header::SphinxHeader;
use crate::payload::key::PayloadKey;
use arrayref::array_ref;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) trait ExpandSecret {
    fn expand_shared_secret(&self) -> ExpandedSharedSecret;
}

impl ExpandSecret for PublicKey {
    fn expand_shared_secret(&self) -> ExpandedSharedSecret {
        self.as_bytes().expand_shared_secret()
    }
}

impl ExpandSecret for SharedSecret {
    fn expand_shared_secret(&self) -> ExpandedSharedSecret {
        self.as_bytes().expand_shared_secret()
    }
}

impl ExpandSecret for [u8; 32] {
    fn expand_shared_secret(&self) -> ExpandedSharedSecret {
        expand_shared_secret(self)
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone, PartialEq, Debug)]
pub struct ExpandedSharedSecret([u8; EXPANDED_SHARED_SECRET_LENGTH]);

impl ExpandedSharedSecret {
    // order of bytes is quite important here to preserve backwards compatibility.
    // replay tag has not been used before so it **has to** be created last

    /// Output of the hρ random oracle
    pub(crate) fn stream_cipher_key(&self) -> &StreamCipherKey {
        array_ref!(&self.0, 0, STREAM_CIPHER_KEY_SIZE)
    }

    /// Output of the hμ random oracle
    pub(crate) fn header_integrity_hmac_key(&self) -> &HeaderIntegrityMacKey {
        array_ref!(&self.0, STREAM_CIPHER_KEY_SIZE, INTEGRITY_MAC_KEY_SIZE)
    }

    /// Legacy output of the hπ random oracle
    // NOTE: currently we expand it to full PRP key
    pub(crate) fn legacy_payload_key(&self) -> &PayloadKey {
        array_ref!(
            &self.0,
            STREAM_CIPHER_KEY_SIZE + INTEGRITY_MAC_KEY_SIZE,
            PAYLOAD_KEY_SIZE
        )
    }

    /// Output of the hπ random oracle
    pub(crate) fn payload_key_seed(&self) -> &[u8; PAYLOAD_KEY_SEED_SIZE] {
        array_ref!(
            &self.0,
            STREAM_CIPHER_KEY_SIZE + INTEGRITY_MAC_KEY_SIZE,
            PAYLOAD_KEY_SEED_SIZE
        )
    }

    /// Output of the hb random oracle
    pub(crate) fn blinding_factor_bytes(&self) -> &[u8; BLINDING_FACTOR_SIZE] {
        array_ref!(
            &self.0,
            STREAM_CIPHER_KEY_SIZE + INTEGRITY_MAC_KEY_SIZE + PAYLOAD_KEY_SIZE,
            BLINDING_FACTOR_SIZE
        )
    }

    pub(crate) fn blinding_factor(&self) -> StaticSecret {
        StaticSecret::from(*self.blinding_factor_bytes())
    }

    pub(crate) fn blind_shared_secret(&self, shared_secret: PublicKey) -> PublicKey {
        SphinxHeader::blind_the_shared_secret(shared_secret, self.blinding_factor())
    }

    /// Output of the h𝜏 random oracle
    pub fn replay_tag(&self) -> &[u8; REPLAY_TAG_SIZE] {
        array_ref!(
            &self.0,
            STREAM_CIPHER_KEY_SIZE
                + INTEGRITY_MAC_KEY_SIZE
                + PAYLOAD_KEY_SIZE
                + BLINDING_FACTOR_SIZE,
            REPLAY_TAG_SIZE
        )
    }
}

pub(crate) fn expand_shared_secret(shared_secret: &[u8; 32]) -> ExpandedSharedSecret {
    let hkdf = Hkdf::<Sha256>::new(Some(EXPANDED_SHARED_SECRET_HKDF_SALT), shared_secret);

    let mut output = [0u8; EXPANDED_SHARED_SECRET_LENGTH];
    // SAFETY: the length of the provided okm is within the allowed range
    #[allow(clippy::unwrap_used)]
    hkdf.expand(EXPANDED_SHARED_SECRET_HKDF_INFO, &mut output)
        .unwrap();

    ExpandedSharedSecret(output)
}

#[cfg(test)]
mod expanding_shared_secret {
    use super::*;
    use crate::test_utils::fixtures::mock_shared_secret;
    use crate::test_utils::{assert_zeroize, assert_zeroize_on_drop, seeded_rng};

    #[test]
    fn expanded_shared_secret_is_zeroized() {
        assert_zeroize::<ExpandedSharedSecret>();
        assert_zeroize_on_drop::<ExpandedSharedSecret>();
    }

    // using old values from legacy `RoutingKeys`
    #[test]
    fn results_in_same_values_as_old_implementation() {
        let mut rng = seeded_rng([1u8; 32]);
        let ss = mock_shared_secret(&mut rng);

        let expected_sck = [
            186, 234, 152, 113, 202, 124, 191, 228, 173, 89, 91, 8, 127, 251, 214, 200,
        ];
        let expected_hihk = [
            28, 222, 17, 227, 46, 180, 170, 7, 34, 52, 177, 142, 150, 137, 142, 222,
        ];
        let expected_pk = [
            210, 209, 81, 241, 254, 123, 36, 81, 155, 85, 115, 40, 101, 210, 97, 8, 196, 104, 61,
            23, 165, 190, 191, 236, 203, 69, 15, 230, 70, 100, 161, 136, 53, 88, 116, 118, 81, 57,
            58, 181, 232, 102, 149, 93, 239, 255, 156, 205, 0, 146, 110, 117, 137, 59, 102, 170,
            87, 250, 175, 207, 193, 107, 112, 154, 247, 220, 110, 135, 32, 106, 20, 152, 14, 132,
            89, 154, 249, 24, 176, 40, 30, 182, 195, 209, 124, 59, 58, 201, 209, 255, 80, 151, 109,
            226, 157, 232, 48, 128, 56, 159, 90, 168, 229, 60, 106, 14, 50, 215, 198, 200, 168, 24,
            159, 224, 240, 119, 23, 242, 61, 129, 54, 36, 140, 245, 127, 159, 230, 5, 52, 142, 254,
            52, 168, 171, 139, 100, 206, 16, 94, 219, 68, 113, 141, 159, 4, 233, 189, 144, 164,
            202, 180, 74, 214, 66, 96, 185, 70, 191, 155, 18, 210, 52, 123, 71, 231, 225, 79, 0,
            196, 25, 217, 231, 133, 191, 96, 119, 103, 182, 200, 36, 215, 62, 203, 149, 214, 139,
            32, 70, 66, 30, 63, 102,
        ];
        let expected_bf = [
            227, 64, 184, 235, 140, 62, 232, 172, 235, 42, 58, 169, 241, 253, 245, 2, 136, 149, 74,
            48, 6, 165, 145, 133, 190, 105, 222, 218, 248, 172, 49, 188,
        ];

        let expanded = expand_shared_secret(ss.as_bytes());
        assert_eq!(expanded.stream_cipher_key(), &expected_sck);
        assert_eq!(expanded.header_integrity_hmac_key(), &expected_hihk);
        assert_eq!(expanded.legacy_payload_key(), &expected_pk);
        assert_eq!(expanded.blinding_factor_bytes(), &expected_bf);
    }
}
