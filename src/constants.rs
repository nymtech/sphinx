use crate::crypto;

// AVERAGE_DELAY SHOULD NEVER BE ZERO!!
pub const AVERAGE_DELAY: f64 = 10.0;
// k in the Sphinx paper. Measured in bytes; 128 bits.
pub const SECURITY_PARAMETER: usize = 16;
// r in the Sphinx paper
pub const MAX_PATH_LENGTH: usize = 5;
pub const ROUTING_KEYS_LENGTH: usize =
    crypto::STREAM_CIPHER_KEY_SIZE + INTEGRITY_MAC_KEY_SIZE + PAYLOAD_KEY_SIZE;
pub const HKDF_INPUT_SEED: &[u8; 97] = b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh.";
pub const STREAM_CIPHER_OUTPUT_LENGTH: usize = (3 * MAX_PATH_LENGTH + 3) * SECURITY_PARAMETER;
pub const DESTINATION_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const NODE_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const IDENTIFIER_LENGTH: usize = SECURITY_PARAMETER;
pub const INTEGRITY_MAC_KEY_SIZE: usize = SECURITY_PARAMETER;
pub const HEADER_INTEGRITY_MAC_SIZE: usize = SECURITY_PARAMETER;
pub const PAYLOAD_KEY_SIZE: usize = 192; // must be 192 because of the Lioness implementation we're using
