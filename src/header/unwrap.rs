use crate::constants::{SECURITY_PARAMETER, STREAM_CIPHER_OUTPUT_LENGTH};
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
) -> (SphinxHeader, Hop) {
    // we have to add padding to the encrypted routing information before decrypting, otherwise we gonna lose information
    let decrypted_routing_information = header
        .routing_info
        .enc_routing_information
        .add_zero_padding()
        .decrypt(stream_cipher_key);

    // TODO: parse the decrypted result to get next_hop, delay, next_routing_info etc.

    (
        SphinxHeader {
            shared_secret: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            routing_info: routing::encapsulated_routing_information_fixture(),
        },
        Hop {
            host: header::RouteElement::ForwardHop(MixNode {
                address: header::node_address_fixture(),
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            }),
            delay: 0.0,
        },
    )
}
