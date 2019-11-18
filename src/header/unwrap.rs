use crate::constants::{INTEGRITY_MAC_SIZE, STREAM_CIPHER_OUTPUT_LENGTH};
use crate::header::header;
use crate::header::header::MixNode;
use crate::header::routing;
use crate::header::routing::{RoutingInformation, RoutingKeys, StreamCipherKey, ROUTING_INFO_SIZE};
use crate::header::SphinxHeader;
use crate::utils;
use crate::utils::crypto;
use crate::Hop;

#[derive(Debug)]
pub enum SphinxUnwrapError {
    IntegrityMacError,
}

pub fn process_header(
    header: SphinxHeader,
    routing_keys: &RoutingKeys,
) -> Result<(SphinxHeader, Hop), SphinxUnwrapError> {
    if !check_integrity_mac(
        header.routing_info.header_integrity_hmac,
        routing_keys.header_integrity_hmac_key,
        header.routing_info.enc_header,
    ) {
        return Err(SphinxUnwrapError::IntegrityMacError);
    }

    let unwrapped_routing_info = decrypt_routing_info(
        routing_keys.stream_cipher_key,
        &header.routing_info.enc_header,
    );

    Ok((
        SphinxHeader {
            shared_secret: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            routing_info: routing::RoutingInfo {
                enc_header: [0u8; ROUTING_INFO_SIZE],
                header_integrity_hmac: [0u8; INTEGRITY_MAC_SIZE],
            },
        },
        Hop {
            host: header::RouteElement::ForwardHop(MixNode {
                address: header::node_address_fixture(),
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            }),
            delay: 0.0,
        },
    ))
}

fn check_integrity_mac(
    integrity_mac: routing::HeaderIntegrityMac,
    integrity_mac_key: routing::HeaderIntegrityMacKey,
    enc_routing_info: RoutingInformation,
) -> bool {
    let recomputed_integrity_mac =
        routing::generate_routing_info_integrity_mac(integrity_mac_key, enc_routing_info);
    if integrity_mac != recomputed_integrity_mac {
        return false;
    }
    return true;
}

pub fn decrypt_routing_info(
    key: StreamCipherKey,
    routing_info_components: &[u8],
) -> RoutingInformation {
    assert_eq!(ROUTING_INFO_SIZE, routing_info_components.len());

    let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
        &key,
        &crypto::STREAM_CIPHER_INIT_VECTOR,
        STREAM_CIPHER_OUTPUT_LENGTH,
    );

    let decrypted_routing_info_vec = utils::bytes::xor(
        &routing_info_components,
        &pseudorandom_bytes[..ROUTING_INFO_SIZE],
    );

    let mut decrypted_routing_info = [0u8; ROUTING_INFO_SIZE];
    decrypted_routing_info.copy_from_slice(&decrypted_routing_info_vec);
    decrypted_routing_info
}

#[cfg(test)]
mod checking_integrity_mac {
    use super::*;
    use crate::constants::INTEGRITY_MAC_KEY_SIZE;

    #[test]
    fn it_returns_true_if_mac_matching() {
        let data = [1u8; ROUTING_INFO_SIZE];
        let mac_key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let hmac = routing::generate_routing_info_integrity_mac(mac_key, data);

        assert_eq!(true, check_integrity_mac(hmac, mac_key, data));
    }

    #[test]
    fn it_returns_false_if_mac_not_matching() {
        let data = [1u8; ROUTING_INFO_SIZE];
        let mac_key = [2u8; INTEGRITY_MAC_KEY_SIZE];
        let hmac = [0u8; INTEGRITY_MAC_SIZE];

        assert_eq!(false, check_integrity_mac(hmac, mac_key, data));
    }
}
