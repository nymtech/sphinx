use crate::{
    header::{self, delays::Delay, HEADER_SIZE},
    payload::{Payload, PAYLOAD_OVERHEAD_SIZE},
    route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier},
    Error, ErrorKind, Result,
};
use builder::SphinxPacketBuilder;
use curve25519_dalek::scalar::Scalar;
use header::{ProcessedHeader, SphinxHeader};

pub mod builder;

pub enum ProcessedPacket {
    // TODO: considering fields sizes here (`SphinxPacket` and `Payload`), we perhaps
    // should follow clippy recommendation and box it
    ProcessedPacketForwardHop(SphinxPacket, NodeAddressBytes, Delay),
    ProcessedPacketFinalHop(DestinationAddressBytes, SURBIdentifier, Payload),
}

#[derive(Clone)]
pub struct SphinxPacket {
    pub header: header::SphinxHeader,
    pub payload: Payload,
}

impl SphinxPacket {
    // `new` works as before and does not care about changes made; it uses default values everywhere
    pub fn new(
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
    ) -> Result<SphinxPacket> {
        SphinxPacketBuilder::default().build_packet(message, route, destination, delays)
    }

    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node
    pub fn process(self, node_secret_key: Scalar) -> Result<ProcessedPacket> {
        let unwrapped_header = self.header.process(node_secret_key)?;
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
                Ok(ProcessedPacket::ProcessedPacketForwardHop(
                    new_packet,
                    next_hop_address,
                    delay,
                ))
            }
            ProcessedHeader::ProcessedHeaderFinalHop(destination, identifier, payload_key) => {
                let new_payload = self.payload.unwrap(&payload_key);
                Ok(ProcessedPacket::ProcessedPacketFinalHop(
                    destination,
                    identifier,
                    new_payload,
                ))
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // with payloads being dynamic in size, the only thing we can do
        // is to check if it at least is longer than the minimum length
        if bytes.len() < HEADER_SIZE + PAYLOAD_OVERHEAD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPacket,
                format!(
                    "tried to recover sphinx packet using {} bytes, expected at least {}",
                    bytes.len(),
                    HEADER_SIZE + PAYLOAD_OVERHEAD_SIZE
                ),
            ));
        }

        let header_bytes = &bytes[..HEADER_SIZE];
        let payload_bytes = &bytes[HEADER_SIZE..];
        let header = SphinxHeader::from_bytes(header_bytes)?;
        let payload = Payload::from_bytes(payload_bytes)?;

        Ok(SphinxPacket { header, payload })
    }
}

#[cfg(test)]
mod test_building_packet_from_bytes {
    use super::*;

    #[test]
    fn from_bytes_returns_error_if_bytes_are_too_short() {
        let bytes = [0u8; 1];
        let expected = ErrorKind::InvalidPacket;
        match SphinxPacket::from_bytes(&bytes) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when packet bytes too short"),
        };
    }
}
