use curve25519_dalek::scalar::Scalar;

use crate::constants::PAYLOAD_KEY_SIZE;
use crate::header::delays::Delay;
use crate::header::{ProcessedHeader, SphinxHeader, SphinxUnwrapError, HEADER_SIZE};
use crate::payload::{Payload, PAYLOAD_SIZE};
use crate::route::{Destination, Node, NodeAddressBytes, SURBIdentifier};

mod constants;
pub mod crypto;
pub mod header;
mod payload;
pub mod route;
mod utils;

#[derive(Debug)]
pub enum ProcessingError {
    InvalidRoutingInformationLengthError,
    InvalidHeaderLengthError,
    InvalidPayloadLengthError,
    InvalidPacketLengthError,
}

pub enum ProcessedPacket {
    ProcessedPacketForwardHop(SphinxPacket, NodeAddressBytes, Delay),
    ProcessedPacketFinalHop(SURBIdentifier, Payload),
}

pub struct SphinxPacket {
    header: header::SphinxHeader,
    pub payload: Payload,
}

impl SphinxPacket {
    pub fn new(
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
    ) -> SphinxPacket {
        let initial_secret = crypto::generate_secret();
        let (header, payload_keys) =
            header::SphinxHeader::new(initial_secret, route, delays, destination);
        let payload = Payload::encapsulate_message(&message, &payload_keys, destination.address);
        SphinxPacket { header, payload }
    }

    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node
    pub fn process(self, node_secret_key: Scalar) -> ProcessedPacket {
        let unwrapped_header = self.header.process(node_secret_key).unwrap();
        match unwrapped_header {
            ProcessedHeader::ProcessedHeaderForwardHop(
                new_header,
                next_hop_address,
                delay,
                payload_key,
            ) => {
                let new_payload = self.payload.unwrap(&payload_key);
                let new_packet = SphinxPacket {
                    header: new_header,
                    payload: new_payload,
                };
                ProcessedPacket::ProcessedPacketForwardHop(new_packet, next_hop_address, delay)
            }
            ProcessedHeader::ProcessedHeaderFinalHop(destination, identifier, payload_key) => {
                let new_payload = self.payload.unwrap(&payload_key);
                ProcessedPacket::ProcessedPacketFinalHop(identifier, new_payload)
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.header
            .to_bytes()
            .iter()
            .cloned()
            .chain(self.payload.get_content_ref().iter().cloned())
            .collect()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProcessingError> {
        // TODO: currently it's defined as minimum size. It should be always constant length in the future
        // once we decide on payload size
        if bytes.len() < HEADER_SIZE + PAYLOAD_SIZE {
            return Err(ProcessingError::InvalidPacketLengthError);
        }

        let header_bytes = bytes[..HEADER_SIZE].to_vec();
        let payload_bytes = bytes[HEADER_SIZE..].to_vec();
        let header = SphinxHeader::from_bytes(header_bytes)?;
        let payload = Payload::from_bytes(payload_bytes)?;

        Ok(SphinxPacket { header, payload })
    }
}
