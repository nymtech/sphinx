use crate::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH};
use crate::utils::crypto;

// I think everything from below here should be moved to main sphinx file or perhaps to something for route

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

pub type DestinationAddressBytes = [u8; DESTINATION_ADDRESS_LENGTH];
pub type NodeAddressBytes = [u8; NODE_ADDRESS_LENGTH];
pub type SURBIdentifier = [u8; IDENTIFIER_LENGTH];

#[derive(Clone)]
pub struct Destination {
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
    RouteElement::FinalHop(Destination {
        address: [3u8; DESTINATION_ADDRESS_LENGTH],
        identifier: [4u8; IDENTIFIER_LENGTH],
        pub_key: crypto::generate_random_curve_point(),
    })
}
