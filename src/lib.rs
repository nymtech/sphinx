// Copyright 2020 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::constants::{DESTINATION_ADDRESS_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER};
use crate::error::ErrorKind;
pub use crate::error::{Error, Result};
use crate::header::delays::Delay;
use crate::header::{ProcessedHeader, SphinxHeader, HEADER_SIZE};
use crate::payload::Payload;
use crate::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes, SURBIdentifier};
use crate::surb::SURB;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

pub mod constants;
pub mod crypto;
pub mod header;
pub mod key;
pub mod payload;
pub mod route;
pub mod surb;
mod utils;

pub const PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
const DEFAULT_RNG: rand_core::OsRng = rand_core::OsRng;

// cleaned-up modules + imports here:
pub mod error;

pub enum ProcessedPacket {
    // TODO: considering fields sizes here (`SphinxPacket` and `Payload`), we perhaps
    // should follow clippy recommendation and box it
    ProcessedPacketForwardHop(SphinxPacket, NodeAddressBytes, Delay),
    ProcessedPacketFinalHop(DestinationAddressBytes, SURBIdentifier, Payload),
}

pub struct SURBMaterial {
    pub surb_route: Vec<Node>,
    pub surb_delays: Vec<Delay>,
    pub surb_destination: Destination,
}

#[derive(Clone)]
pub struct SphinxPacket {
    pub header: header::SphinxHeader,
    pub payload: Payload,
}

impl SphinxPacket {
    pub fn new(
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        surb_material: Option<SURBMaterial>,
    ) -> Result<SphinxPacket> {
        Self::new_with_rng(
            &mut DEFAULT_RNG,
            message,
            route,
            destination,
            delays,
            surb_material,
        )
    }

    pub fn new_with_rng<R: RngCore + CryptoRng>(
        mut rng: R,
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        surb_material: Option<SURBMaterial>,
    ) -> Result<SphinxPacket> {
        let initial_secret = crypto::generate_secret(&mut rng);
        let (header, payload_keys) =
            header::SphinxHeader::new(initial_secret, route, delays, destination);

        let mut plaintext = message.clone();

        if let Some(surb_material) = surb_material {
            let surb_initial_secret = crypto::generate_secret(&mut rng);
            let surb = SURB::new(
                surb_initial_secret,
                &surb_material.surb_route,
                &surb_material.surb_delays,
                &surb_material.surb_destination,
            )?;

            plaintext = surb
                .to_bytes()
                .iter()
                .cloned()
                .chain(message.iter().cloned())
                .collect();
        }

        if plaintext.len() + DESTINATION_ADDRESS_LENGTH > PAYLOAD_SIZE - SECURITY_PARAMETER {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "too long plaintext message provided",
            ));
        }
        let payload =
            Payload::encapsulate_message(&plaintext, &payload_keys, destination.address.clone())?;
        Ok(SphinxPacket { header, payload })
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
        if bytes.len() != PACKET_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidPacket,
                format!(
                    "tried to recover sphinx packet using {} bytes, expected {}",
                    bytes.len(),
                    PACKET_SIZE
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

    #[test]
    fn from_bytes_panics_if_bytes_are_too_long() {
        let bytes = [0u8; 6666];
        let expected = ErrorKind::InvalidPacket;
        match SphinxPacket::from_bytes(&bytes) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when packet bytes too long"),
        };
    }
}
