use crate::header::{MixNode, RouteElement, SphinxHeader};

mod constants;
mod crypto;
mod header;
mod payload;

pub struct SphinxPacket {
    header: SphinxHeader,
    payload: Vec<u8>,
}

pub fn create_packet(message: Vec<u8>, route: &[RouteElement]) -> SphinxPacket {
    let (header, shared_keys) = header::create(route);
    let enc_payload = payload::create(message, shared_keys);
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
            host: RouteElement::ForwardHop(MixNode {
                address: header::ipv4_host_fixture(),
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            }),
            delay: 0.0,
        },
    )
}
