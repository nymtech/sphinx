// AVERAGE_DELAY SHOULD NEVER BE ZERO!!
pub const AVERAGE_DELAY: f64 = 10.0;
pub const SECURITY_PARAMETER: usize = 16; // in bytes; 128 bits
pub const MAX_PATH_LENGTH: usize = 5; // what we refer in the Sphinx paper as r
pub const STREAM_CIPHER_KEY_SIZE: usize = 16;
pub const STREAM_CIPHER_INIT_VECTOR: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
pub const ROUTING_KEYS_LENGTH: usize = 2 * STREAM_CIPHER_KEY_SIZE;
pub const HKDF_INPUT_SEED: &[u8; 97] = b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh.";
pub const STREAM_CIPHER_OUTPUT_LENGTH: usize = (2 * MAX_PATH_LENGTH + 3) * SECURITY_PARAMETER;
