use crate::header::HKDFSalt;
use crate::{
    crypto::EphemeralSecret,
    header::{delays::Delay, SphinxHeader},
    payload::Payload,
    route::{Destination, Node},
    Result, SphinxPacket,
};

pub const DEFAULT_PAYLOAD_SIZE: usize = 1024;

pub struct SphinxPacketBuilder<'a> {
    payload_size: usize,
    initial_secret: Option<&'a EphemeralSecret>,
}

impl<'a> SphinxPacketBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_payload_size(mut self, payload_size: usize) -> Self {
        self.payload_size = payload_size;
        self
    }

    pub fn with_initial_secret(mut self, initial_secret: &'a EphemeralSecret) -> Self {
        self.initial_secret = Some(initial_secret);
        self
    }

    pub fn build_packet(
        &self,
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        hkdf_salt: &[HKDFSalt],
    ) -> Result<SphinxPacket> {
        let (header, payload_keys) = match self.initial_secret.as_ref() {
            Some(initial_secret) => {
                SphinxHeader::new(initial_secret, route, delays, hkdf_salt, destination)
            }
            None => SphinxHeader::new(
                &EphemeralSecret::new(),
                route,
                delays,
                hkdf_salt,
                destination,
            ),
        };

        // no need to check if plaintext has correct length as this check is already performed in payload encapsulation
        let payload = Payload::encapsulate_message(&message, &payload_keys, self.payload_size)?;
        Ok(SphinxPacket { header, payload })
    }
}

impl<'a> Default for SphinxPacketBuilder<'a> {
    fn default() -> Self {
        SphinxPacketBuilder {
            payload_size: DEFAULT_PAYLOAD_SIZE,
            initial_secret: None,
        }
    }
}
