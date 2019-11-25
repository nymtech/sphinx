use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use curve25519_dalek::scalar::Scalar;

mod constants;
pub mod crypto;
mod header;
mod payload;
pub mod route;
mod utils;

pub struct SphinxPacket {
    header: header::SphinxHeader,
    pub payload: Payload,
}

impl SphinxPacket {
    pub fn new(message: Vec<u8>, route: &[Node], destination: &Destination) -> SphinxPacket {
        let initial_secret = crypto::generate_secret();
        let (header, payload_keys) = header::SphinxHeader::new(initial_secret, route, destination);
        let payload = Payload::encapsulate_message(&message, &payload_keys, destination.address);
        SphinxPacket { header, payload }
    }

    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node
    pub fn process(self, node_secret_key: Scalar) -> (SphinxPacket, NodeAddressBytes) {
        let unwrapped_header = self.header.process(node_secret_key).unwrap();
        let (new_header, next_hop_address, payload_key) = unwrapped_header;

        // process the payload
        let new_payload = self.payload.unwrap(&payload_key);

        (
            SphinxPacket {
                header: new_header,
                payload: new_payload,
            },
            next_hop_address,
        )
    }

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    pub fn from_bytes() -> Option<SphinxPacket> {
        //        SphinxPacket {
        //            header: SphinxHeader {
        //                shared_secret: Default::default(),
        //                routing_info: EncapsulatedRoutingInformation {
        //                    enc_routing_information: (),
        //                    integrity_mac: (),
        //                },
        //            },
        //            payload: vec![],
        //        }
        None
    }
}
