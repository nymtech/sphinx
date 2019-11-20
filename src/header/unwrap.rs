use crate::constants::{
    HEADER_INTEGRITY_MAC_SIZE, NODE_ADDRESS_LENGTH, SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH,
};
use crate::header::header;
use crate::header::header::MixNode;
use crate::header::keys::StreamCipherKey;
use crate::header::routing;
use crate::header::routing::{
    EncryptedRoutingInformation, PaddedEncryptedRoutingInformation, ROUTING_INFO_SIZE,
};
use crate::header::SphinxHeader;
use crate::utils;
use crate::utils::crypto;
use crate::Hop;

pub fn unwrap_routing_information(
    enc_routing_information: EncryptedRoutingInformation,
    stream_cipher_key: StreamCipherKey,
) -> (
    [u8; NODE_ADDRESS_LENGTH],
    [u8; HEADER_INTEGRITY_MAC_SIZE],
    [u8; ROUTING_INFO_SIZE],
) {
    // we have to add padding to the encrypted routing information before decrypting, otherwise we gonna lose information
    let decrypted_routing_information = enc_routing_information
        .add_zero_padding()
        .decrypt(stream_cipher_key);

    parse_decrypted_routing_information(decrypted_routing_information)
}

fn parse_decrypted_routing_information(
    decrypted_routing_information: Vec<u8>,
) -> (
    [u8; NODE_ADDRESS_LENGTH],
    [u8; HEADER_INTEGRITY_MAC_SIZE],
    [u8; ROUTING_INFO_SIZE],
) {
    let mut next_hop_addr: [u8; NODE_ADDRESS_LENGTH] = Default::default();
    next_hop_addr.copy_from_slice(&decrypted_routing_information[..NODE_ADDRESS_LENGTH]);

    let mut next_hop_integrity_mac: [u8; HEADER_INTEGRITY_MAC_SIZE] = Default::default();
    next_hop_integrity_mac.copy_from_slice(
        &decrypted_routing_information
            [NODE_ADDRESS_LENGTH..NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE],
    );

    let mut next_hop_encrypted_routing_information = [0u8; ROUTING_INFO_SIZE];
    next_hop_encrypted_routing_information.copy_from_slice(
        &decrypted_routing_information[NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE
            ..NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE + ROUTING_INFO_SIZE],
    );

    (
        next_hop_addr,
        next_hop_integrity_mac,
        next_hop_encrypted_routing_information,
    )
}

#[cfg(test)]
mod unwrap_routing_information {
    use super::*;

    #[test]
    fn it_returns_correct_unwrapped_routing_information() {
        let routing_info = [9u8; ROUTING_INFO_SIZE];
        let stream_cipher_key = [1u8; crypto::STREAM_CIPHER_KEY_SIZE];
        let pseudorandom_bytes = crypto::generate_pseudorandom_bytes(
            &stream_cipher_key,
            &crypto::STREAM_CIPHER_INIT_VECTOR,
            STREAM_CIPHER_OUTPUT_LENGTH,
        );
        let encrypted_routing_info_vec =
            utils::bytes::xor(&routing_info, &pseudorandom_bytes[..ROUTING_INFO_SIZE]);
        let mut encrypted_routing_info = EncryptedRoutingInformation {
            value: [0u8; ROUTING_INFO_SIZE],
        };
        encrypted_routing_info
            .value
            .copy_from_slice(&encrypted_routing_info_vec);

        let expected_next_hop_encrypted_routing_information = [
            routing_info[NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE..].to_vec(),
            pseudorandom_bytes
                [NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE + ROUTING_INFO_SIZE..]
                .to_vec(),
        ]
        .concat();
        let (next_hop_addr, next_hop_integrity_mac, next_hop_encrypted_routing_information) =
            unwrap_routing_information(encrypted_routing_info, stream_cipher_key);

        assert_eq!(routing_info[..NODE_ADDRESS_LENGTH], next_hop_addr);
        assert_eq!(
            routing_info[NODE_ADDRESS_LENGTH..NODE_ADDRESS_LENGTH + HEADER_INTEGRITY_MAC_SIZE],
            next_hop_integrity_mac
        );

        for i in 0..expected_next_hop_encrypted_routing_information.len() {
            assert_eq!(
                expected_next_hop_encrypted_routing_information[i],
                next_hop_encrypted_routing_information[i]
            );
        }
    }
}

#[cfg(test)]
mod parse_decrypted_routing_information {
    use super::*;
    use crate::header::header::node_address_fixture;
    use crate::header::routing::header_integrity_mac_fixture;

    #[test]
    fn it_returns_next_hop_addr_integrity_mac_enc_routing_info() {
        let addr = node_address_fixture();
        let integrity_mac = header_integrity_mac_fixture().get_value();
        let next_routing_information = [1u8; ROUTING_INFO_SIZE];

        let data = [
            addr.to_vec(),
            integrity_mac.to_vec(),
            next_routing_information.to_vec(),
        ]
        .concat();

        let (a, b, c) = parse_decrypted_routing_information(data);
        assert_eq!(addr, a);
        assert_eq!(integrity_mac, b);
        for i in 0..next_routing_information.len() {
            assert_eq!(next_routing_information[i], c[i]);
        }
    }
}
