use crate::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH};
use crate::crypto;

// in paper delta
pub type DestinationAddressBytes = [u8; DESTINATION_ADDRESS_LENGTH];
// in paper nu
pub type NodeAddressBytes = [u8; NODE_ADDRESS_LENGTH];
// in paper I
pub type SURBIdentifier = [u8; IDENTIFIER_LENGTH];

//#[derive(Clone)]
pub struct Destination {
    // address in theory could be changed to a vec<u8> as it does not need to be strictly DESTINATION_ADDRESS_LENGTH long
    // but cannot be longer than that (assuming longest possible route)
    pub address: DestinationAddressBytes,
    pub identifier: SURBIdentifier,
}

impl Destination {
    pub fn new(address: DestinationAddressBytes, identifier: SURBIdentifier) -> Self {
        Self {
            address,
            identifier,
        }
    }
}

//#[derive(Clone)]
pub struct Node {
    pub address: NodeAddressBytes,
    pub pub_key: crypto::PublicKey,
}

impl Node {
    pub fn new(address: NodeAddressBytes, pub_key: crypto::PublicKey) -> Self {
        Self { address, pub_key }
    }
}

pub fn destination_address_fixture() -> DestinationAddressBytes {
    [0u8; DESTINATION_ADDRESS_LENGTH]
}

pub fn node_address_fixture() -> NodeAddressBytes {
    [0u8; NODE_ADDRESS_LENGTH]
}

pub fn surb_identifier_fixture() -> SURBIdentifier {
    [0u8; IDENTIFIER_LENGTH]
}

pub fn random_node() -> Node {
    Node {
        address: [2u8; NODE_ADDRESS_LENGTH],
        pub_key: crypto::generate_random_curve_point(),
    }
}

pub fn destination_fixture() -> Destination {
    Destination {
        address: [3u8; DESTINATION_ADDRESS_LENGTH],
        identifier: [4u8; IDENTIFIER_LENGTH],
    }
}
