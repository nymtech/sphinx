use crate::crypto;

// AVERAGE_DELAY SHOULD NEVER BE ZERO!!
pub const AVERAGE_DELAY: f64 = 10.0; // let's assume we give it in seconds for now
pub const SECURITY_PARAMETER: usize = 16; // k in the Sphinx paper. Measured in bytes; 128 bits.
pub const MAX_PATH_LENGTH: usize = 5; // r in the Sphinx paper
pub const ROUTING_KEYS_LENGTH: usize =
    crypto::STREAM_CIPHER_KEY_SIZE + INTEGRITY_MAC_KEY_SIZE + PAYLOAD_KEY_SIZE;
pub const HKDF_INPUT_SEED: &[u8; 97] = b"Dwste mou enan moxlo arketa makru kai ena upomoxlio gia na ton topothetisw kai tha kinisw thn gh.";
pub const STREAM_CIPHER_OUTPUT_LENGTH: usize =
    (NODE_META_INFO_LENGTH + HEADER_INTEGRITY_MAC_SIZE) * (MAX_PATH_LENGTH + 1);
pub const DESTINATION_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const NODE_ADDRESS_LENGTH: usize = 2 * SECURITY_PARAMETER;
pub const IDENTIFIER_LENGTH: usize = SECURITY_PARAMETER;
pub const INTEGRITY_MAC_KEY_SIZE: usize = SECURITY_PARAMETER;
pub const HEADER_INTEGRITY_MAC_SIZE: usize = SECURITY_PARAMETER;
pub const PAYLOAD_KEY_SIZE: usize = 192; // must be 192 because of the Lioness implementation we're using
pub const DELAY_LENGTH: usize = 8; // how many bytes we will use to encode the delay
pub const NODE_META_INFO_LENGTH: usize = NODE_ADDRESS_LENGTH + FLAG_LENGTH + DELAY_LENGTH; // the meta info is all the information from sender to the node like: where to forward the packet, what is the delay etc
pub const FINAL_NODE_META_INFO_LENGTH: usize =
    DESTINATION_ADDRESS_LENGTH + IDENTIFIER_LENGTH + FLAG_LENGTH; // the meta info for the final hop might be of a different size
pub const FLAG_LENGTH: usize = 1;
pub const PAYLOAD_SIZE: usize = 1024; // at minimum it HAS TO be at least equal to length of the key block used in lioness
