use crate::header::{create_header, Address, Host, RouteElement, SphinxHeader};
use crate::payload::create_enc_payload;

mod constants;
mod crypto;
mod header;
mod payload;

pub struct SphinxPacket {
    header: SphinxHeader,
    payload: Vec<u8>,
}

// TODO: a utility function to turn this into properly concatenated bytes
pub fn create_packet(message: Vec<u8>, route: &[RouteElement]) -> SphinxPacket {
    let (header, shared_keys) = create_header(route);
    let enc_payload = create_enc_payload(message, shared_keys);
    SphinxPacket {
        header,
        payload: enc_payload,
    }
}

// TODO: rethink
pub struct Hop {
    pub host: RouteElement,
    pub delay: f64,
}

// needs the processor's secret key somehow, figure out where this will come from
// the return value could also be a message, handle this
pub fn unwrap_layer(packet: SphinxPacket) -> (SphinxPacket, Hop) {
    (
        SphinxPacket {
            header: SphinxHeader {},
            payload: vec![],
        },
        Hop {
            host: RouteElement::ForwardHop(Host {
                address: header::fakeHost(),
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            }),
            delay: 0.0,
        },
    )
}
