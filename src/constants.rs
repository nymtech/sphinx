use crate::utils::crypto;

// AVERAGE_DELAY SHOULD NEVER BE ZERO!!
pub const AVERAGE_DELAY: f64 = 10.0;
pub const SECURITY_PARAMETER: usize = 16; // in bytes; 128 bits
pub const MAX_PATH_LENGTH: usize = 5; // what we refer in the Sphinx paper as r
pub const ROUTING_KEYS_LENGTH: usize = crypto::STREAM_CIPHER_KEY_SIZE + INTEGRITY_MAC_KEY_SIZE;
pub const HKDF_INPUT_SEED: &[u8; 97] = b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh.";
pub const STREAM_CIPHER_OUTPUT_LENGTH: usize = (2 * MAX_PATH_LENGTH + 3) * SECURITY_PARAMETER;
pub const DESTINATION_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const IDENTIFIER_LENGTH: usize = SECURITY_PARAMETER;
pub const INTEGRITY_MAC_KEY_SIZE: usize = SECURITY_PARAMETER;
