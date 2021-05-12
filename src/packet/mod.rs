use builder::SphinxPacketBuilder;
use header::{ProcessedHeader, SphinxHeader};

use crate::crypto::keys::SharedKey;
use crate::header::HkdfSalt;
use crate::{
    crypto::PrivateKey,
    header::{self, delays::Delay, HEADER_SIZE},
    payload::{Payload, PAYLOAD_OVERHEAD_SIZE},
    route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier},
    Error, ErrorKind, Result,
};

pub mod builder;

pub enum ProcessedPacket {
    // TODO: considering fields sizes here (`SphinxPacket` and `Payload`), we perhaps
    // should follow clippy recommendation and box it
    ForwardHop(SphinxPacket, NodeAddressBytes, Delay),
    FinalHop(DestinationAddressBytes, SURBIdentifier, Payload),
}

impl ProcessedPacket {
    pub fn shared_secret(&self) -> Option<SharedKey> {
        match self {
            ProcessedPacket::ForwardHop(packet, ..) => Some(packet.shared_secret()),
            ProcessedPacket::FinalHop(..) => None,
        }
    }
}

pub struct SphinxPacket {
    pub header: header::SphinxHeader,
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
        hkdf_salt: &[HkdfSalt],
    ) -> Result<SphinxPacket> {
        SphinxPacketBuilder::default().build_packet(message, route, destination, delays, hkdf_salt)
    }

    pub fn new_with_precomputed_keys(
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        hkdf_salt: &[HkdfSalt],
        shared_keys: &[SharedKey],
        initial_shared_secret: &SharedKey,
    ) -> Result<SphinxPacket> {
        SphinxPacketBuilder::default().build_packet_with_precomputed_keys(
            message,
            route,
            destination,
            delays,
            hkdf_salt,
            shared_keys,
            initial_shared_secret,
        )
    }

    pub fn shared_secret(&self) -> SharedKey {
        self.header.shared_secret
    }

    pub fn len(&self) -> usize {
        // header always has constant size
        HEADER_SIZE + self.payload.len()
    }

    /// Processes the packet using a previously derived shared key and a fresh salt.
    /// This function can be used in the situation where sender is re-using initial secret
    /// and the intermediate nodes cash the shared key derived using Diffie Hellman as a
    /// master key, and using only the HKDF and the fresh salt derive an ephemeral key
    /// to process the packet
    pub fn process_with_previously_derived_keys(
        self,
        shared_key: SharedKey,
        hkdf_salt: Option<&HkdfSalt>,
    ) -> Result<ProcessedPacket> {
        let unwrapped_header = self
            .header
            .process_with_previously_derived_keys(shared_key, hkdf_salt)?;
        match unwrapped_header {
            ProcessedHeader::ForwardHop(new_header, next_hop_address, delay, payload_key) => {
                let new_payload = self.payload.unwrap(&payload_key)?;
                let new_packet = SphinxPacket {
                    header: new_header,
                    payload: new_payload,
                };
                Ok(ProcessedPacket::ForwardHop(
                    new_packet,
                    next_hop_address,
                    delay,
                ))
            }
            ProcessedHeader::FinalHop(destination, identifier, payload_key) => {
                let new_payload = self.payload.unwrap(&payload_key)?;
                Ok(ProcessedPacket::FinalHop(
                    destination,
                    identifier,
                    new_payload,
                ))
            }
        }
    }

    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node
    pub fn process(self, node_secret_key: &PrivateKey) -> Result<ProcessedPacket> {
        let unwrapped_header = self.header.process(node_secret_key)?;
        match unwrapped_header {
            ProcessedHeader::ForwardHop(new_header, next_hop_address, delay, payload_key) => {
                let new_payload = self.payload.unwrap(&payload_key)?;
                let new_packet = SphinxPacket {
                    header: new_header,
                    payload: new_payload,
                };
                Ok(ProcessedPacket::ForwardHop(
                    new_packet,
                    next_hop_address,
                    delay,
                ))
            }
            ProcessedHeader::FinalHop(destination, identifier, payload_key) => {
                let new_payload = self.payload.unwrap(&payload_key)?;
                Ok(ProcessedPacket::FinalHop(
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
            .chain(self.payload.as_bytes().iter().cloned())
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
