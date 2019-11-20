use crate::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH};
use crate::utils::crypto;

#[derive(Clone)]
pub enum RouteElement {
    FinalHop(Destination),
    ForwardHop(MixNode),
}

impl RouteElement {
    pub fn get_pub_key(&self) -> crypto::PublicKey {
        use RouteElement::*;

        match self {
            FinalHop(destination) => destination.pub_key,
            ForwardHop(host) => host.pub_key,
        }
    }
}

pub type DestinationAddressBytes = [u8; DESTINATION_ADDRESS_LENGTH]; // in paper delta
pub type NodeAddressBytes = [u8; NODE_ADDRESS_LENGTH]; // in paper nu
pub type SURBIdentifier = [u8; IDENTIFIER_LENGTH]; // in paper I

#[derive(Clone)]
pub struct Destination {
    // address in theory could be changed to a vec<u8> as it does not need to be strictly DESTINATION_ADDRESS_LENGTH long
    // but cannot be longer than that (assuming longest possible route)
    pub address: DestinationAddressBytes,
    pub identifier: SURBIdentifier,
    pub pub_key: crypto::PublicKey,
}

#[derive(Clone)]
pub struct MixNode {
    pub address: NodeAddressBytes,
    pub pub_key: crypto::PublicKey,
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

pub fn random_forward_hop() -> RouteElement {
    RouteElement::ForwardHop(MixNode {
        address: [2u8; NODE_ADDRESS_LENGTH],
        pub_key: crypto::generate_random_curve_point(),
    })
}

pub fn random_final_hop() -> RouteElement {
    RouteElement::FinalHop(random_destination())
}

pub fn random_destination() -> Destination {
    Destination {
        address: [3u8; DESTINATION_ADDRESS_LENGTH],
        identifier: [4u8; IDENTIFIER_LENGTH],
        pub_key: crypto::generate_random_curve_point(),
    }
}
