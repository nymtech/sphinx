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
    header: SphinxHeader,
    stream_cipher_key: StreamCipherKey,
) -> (
    [u8; NODE_ADDRESS_LENGTH],
    [u8; HEADER_INTEGRITY_MAC_SIZE],
    [u8; ROUTING_INFO_SIZE],
) {
    // we have to add padding to the encrypted routing information before decrypting, otherwise we gonna lose information
    let decrypted_routing_information = header
        .routing_info
        .enc_routing_information
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
