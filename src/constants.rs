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

use crate::crypto;
use digest::generic_array::typenum::U16;
use sha2::Sha256;

pub const SECURITY_PARAMETER: usize = 16; // k in the Sphinx paper. Measured in bytes; 128 bits.
pub const MAX_PATH_LENGTH: usize = 5; // r in the Sphinx paper
pub const BLINDING_FACTOR_SIZE: usize = 2 * SECURITY_PARAMETER;
pub const ROUTING_KEYS_LENGTH: usize = crypto::STREAM_CIPHER_KEY_SIZE
    + INTEGRITY_MAC_KEY_SIZE
    + PAYLOAD_KEY_SIZE
    + BLINDING_FACTOR_SIZE;
pub const HKDF_INPUT_SEED: &[u8; 97] = b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh.";
pub const STREAM_CIPHER_OUTPUT_LENGTH: usize =
    (NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE) * (MAX_PATH_LENGTH + 1);
pub const DESTINATION_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const NODE_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const IDENTIFIER_LENGTH: usize = SECURITY_PARAMETER;
pub const INTEGRITY_MAC_KEY_SIZE: usize = SECURITY_PARAMETER;
pub const HEADER_INTEGRITY_MAC_SIZE: usize = SECURITY_PARAMETER;
pub const PAYLOAD_KEY_SIZE: usize = 192; // must be 192 because of the Lioness implementation we're using
pub const DELAY_LENGTH: usize = 8; // how many bytes we will use to encode the delay
pub const NODE_META_INFO_SIZE: usize =
    NODE_ADDRESS_LENGTH + FLAG_LENGTH + DELAY_LENGTH + VERSION_LENGTH; // the meta info is all the information from sender to the node like: where to forward the packet, what is the delay etc
pub const FINAL_NODE_META_INFO_LENGTH: usize =
    DESTINATION_ADDRESS_LENGTH + IDENTIFIER_LENGTH + FLAG_LENGTH + VERSION_LENGTH; // the meta info for the final hop might be of a different size
pub const FLAG_LENGTH: usize = 1;
pub const PAYLOAD_SIZE: usize = 1024;
pub const VERSION_LENGTH: usize = 3; // since version is represented as 3 u8 values: major, minor and patch
                                     // we need the single byte to detect padding length
pub const FIXEDNONCE: [u8; 32] = [
    30, 84, 167, 175, 87, 239, 237, 174, 64, 121, 126, 161, 95, 115, 224, 107, 178, 133, 122, 30,
    53, 122, 169, 193, 243, 212, 31, 218, 167, 110, 108, 170,
];
pub type HeaderIntegrityMacSize = U16;

// TODO: to replace with Blake3
pub type HeaderIntegrityHmacAlgorithm = Sha256;

#[cfg(test)]
mod tests {
    use super::*;
    use digest::generic_array::typenum::Unsigned;

    #[test]
    fn generic_type_sizes_are_consistent_with_defined_constants() {
        assert_eq!(
            HeaderIntegrityMacSize::to_usize(),
            HEADER_INTEGRITY_MAC_SIZE
        )
    }
}
