use curve25519_dalek::scalar::Scalar;

use crate::route::{Destination, Node, NodeAddressBytes};

mod constants;
pub mod crypto;
mod header;
mod payload;
pub mod route;
mod utils;

pub struct SphinxPacket {
    header: header::SphinxHeader,
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    pub fn create(message: Vec<u8>, route: &[Node], destination: &Destination) -> SphinxPacket {
        let initial_secret = crypto::generate_secret();
        let (header, payload_keys) = header::create(initial_secret, route, destination);
        let payload = payload::create(&message, payload_keys, destination.address);
        SphinxPacket { header, payload }
    }

    // TODO: needs the processor's secret key somehow, so far I'm just passing it the return value could also be a message, handle this
    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node
    pub fn process(self, node_secret_key: Scalar) -> (SphinxPacket, NodeAddressBytes) {
        let unwrapped_header = header::process_header(self.header, node_secret_key).unwrap();
        let (new_header, next_hop_address, payload_key) = unwrapped_header;

        // process the payload
        let new_payload = payload::unwrap::unwrap_payload(self.payload, &payload_key);

        (
            SphinxPacket {
                header: new_header,
                payload: new_payload,
            },
            next_hop_address,
        )
    }
}
