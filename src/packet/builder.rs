use crate::version::Version;
use crate::{
    header::{delays::Delay, SphinxHeader},
    payload::Payload,
    route::{Destination, Node},
    Result, SphinxPacket,
};
use x25519_dalek::StaticSecret;

pub const DEFAULT_PAYLOAD_SIZE: usize = 1024;

pub struct SphinxPacketBuilder<'a> {
    payload_size: usize,
    initial_secret: Option<&'a StaticSecret>,
    version: Version,
}

impl<'a> SphinxPacketBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    #[must_use]
    pub fn with_payload_size(mut self, payload_size: usize) -> Self {
        self.payload_size = payload_size;
        self
    }

    #[must_use]
    pub fn with_initial_secret(mut self, initial_secret: &'a StaticSecret) -> Self {
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
        let initial_secret = match self.initial_secret.as_ref() {
            Some(initial_secret) => initial_secret,
            None => &StaticSecret::random(),
        };

        let built_header =
            SphinxHeader::new_versioned(initial_secret, route, delays, destination, self.version);

        let payload_keys = built_header.derive_payload_keys();
        let header = built_header.into_header();

        // no need to check if plaintext has correct length as this check is already performed in payload encapsulation
        let payload =
            Payload::encapsulate_message(message.as_ref(), &payload_keys, self.payload_size)?;
        Ok(SphinxPacket { header, payload })
    }
}

impl Default for SphinxPacketBuilder<'_> {
    fn default() -> Self {
        SphinxPacketBuilder {
            payload_size: DEFAULT_PAYLOAD_SIZE,
            initial_secret: None,
            version: Default::default(),
        }
    }
}
