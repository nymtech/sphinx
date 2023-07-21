use crate::{
    crypto::EphemeralSecret,
    header::{delays::Delay, SphinxHeader},
    payload::Payload,
    route::{Destination, Node},
    Result, SphinxPacket,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

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

    pub fn build_packet<M: AsRef<[u8]>>(
        &self,
        message: M,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
    ) -> Result<SphinxPacket> {
        self.build_packet_with_rng(message, route, destination, delays, &mut OsRng)
    }

    pub fn build_packet_with_rng<R: RngCore + CryptoRng, M: AsRef<[u8]>>(
        &self,
        message: M,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        rng: &mut R,
    ) -> Result<SphinxPacket> {
        let (header, payload_keys) = match self.initial_secret.as_ref() {
            Some(initial_secret) => {
                SphinxHeader::new_with_rng(initial_secret, route, delays, destination, rng)
            }
            None => SphinxHeader::new_with_rng(
                &EphemeralSecret::new_with_rng(rng),
                route,
                delays,
                destination,
                rng,
            ),
        };

        // no need to check if plaintext has correct length as this check is already performed in payload encapsulation
        let payload =
            Payload::encapsulate_message(message.as_ref(), &payload_keys, self.payload_size)?;
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
