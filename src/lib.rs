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

// andrew: if this is our public facing API, should we require users to pass an initial secret?
pub fn create_packet(
    initial_secret: Scalar,
    message: Vec<u8>,
    route: &[Node],
    destination: &Destination,
) -> SphinxPacket {
    let (header, payload_keys) = header::create(initial_secret, route, destination);
    let payload = payload::create(&message, payload_keys, destination.address);
    SphinxPacket { header, payload }
}

// needs the processor's secret key somehow, so far I'm just passing it
// the return value could also be a message, handle this
pub fn process_packet(
    packet: SphinxPacket,
    node_secret_key: Scalar,
) -> (SphinxPacket, NodeAddressBytes) {
    //-> Result<(SphinxPacket, Hop), SphinxUnwrapError> {
    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node

    let unwrapped_header = header::process_header(packet.header, node_secret_key).unwrap();
    let (new_header, next_hop_addr, payload_key) = unwrapped_header;

    // process the payload
    let new_payload = payload::unwrap::unwrap_payload(packet.payload, &payload_key);

    (
        SphinxPacket {
            header: new_header,
            payload: new_payload,
        },
        next_hop_addr,
    )
}
