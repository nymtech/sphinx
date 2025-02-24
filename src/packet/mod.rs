use crate::header::keys::RoutingKeys;
use crate::version::Version;
use crate::{
    header::{self, delays::Delay, HEADER_SIZE},
    payload::{Payload, PAYLOAD_OVERHEAD_SIZE},
    route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier},
    Error, ErrorKind, Result,
};
use builder::SphinxPacketBuilder;
use header::SphinxHeader;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod builder;

pub struct ProcessedPacket {
    pub version: Version,
    pub data: ProcessedPacketData,
}

pub enum ProcessedPacketData {
    ForwardHop {
        next_hop_packet: SphinxPacket,
        next_hop_address: NodeAddressBytes,
        delay: Delay,
    },
    FinalHop {
        destination: DestinationAddressBytes,
        identifier: SURBIdentifier,
        payload: Payload,
    },
}

impl ProcessedPacket {
    pub fn shared_secret(&self) -> Option<PublicKey> {
        match &self.data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet, ..
            } => Some(next_hop_packet.shared_secret()),
            ProcessedPacketData::FinalHop { .. } => None,
        }
    }
}

pub struct SphinxPacket {
    pub header: SphinxHeader,
    pub payload: Payload,
}

#[allow(clippy::len_without_is_empty)]
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

    pub fn shared_secret(&self) -> PublicKey {
        self.header.shared_secret
    }

    pub fn len(&self) -> usize {
        // header always has constant size
        HEADER_SIZE + self.payload.len()
    }

    /// Processes the header with the provided derived keys.
    /// It could be useful in the situation where sender is re-using initial secret
    /// and we could cache processing results.
    ///
    /// However, unless you know exactly what you are doing, you should NEVER use this method!
    /// Prefer normal [process] instead.
    #[deprecated]
    pub fn process_with_derived_keys(
        self,
        new_blinded_secret: &Option<PublicKey>,
        routing_keys: &RoutingKeys,
    ) -> Result<ProcessedPacket> {
        let unwrapped_header = self
            .header
            .process_with_derived_keys(new_blinded_secret, routing_keys)?;
        let unwrapped_payload = self.payload.unwrap(unwrapped_header.payload_key())?;

        Ok(unwrapped_header.attach_payload(unwrapped_payload))
    }

    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node
    pub fn process(self, node_secret_key: &StaticSecret) -> Result<ProcessedPacket> {
        let unwrapped_header = self.header.process(node_secret_key)?;
        let unwrapped_payload = self.payload.unwrap(unwrapped_header.payload_key())?;

        Ok(unwrapped_header.attach_payload(unwrapped_payload))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.header
            .to_bytes()
            .iter()
            .copied()
            .chain(self.payload.as_bytes().iter().copied())
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
