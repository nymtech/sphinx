use crate::{
    crypto,
    header::{delays::Delay, SphinxHeader},
    payload::Payload,
    route::{Destination, Node},
    Result, SphinxPacket,
};

pub const DEFAULT_PAYLOAD_SIZE: usize = 1024;

pub struct SphinxPacketBuilder {
    payload_size: usize,
    // I'm still not entirely convinced it should live here rather than in `common/nymsphinx`
    // surb_material: Option<SURBMaterial>,
}

impl SphinxPacketBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_payload_size(mut self, payload_size: usize) -> Self {
        self.payload_size = payload_size;
        self
    }

    pub fn build_packet(
        &self,
        message: Vec<u8>,
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
    ) -> Result<SphinxPacket> {
        let initial_secret = crypto::generate_secret();
        let (header, payload_keys) = SphinxHeader::new(initial_secret, route, delays, destination);

        // no need to check for if plaintext has correct length as this check is already performed in payload encapsulation
        let payload = Payload::encapsulate_message(
            &message,
            &payload_keys,
            destination.address.clone(),
            self.payload_size,
        )?;
        Ok(SphinxPacket { header, payload })
    }
}

impl Default for SphinxPacketBuilder {
    fn default() -> Self {
        SphinxPacketBuilder {
            payload_size: DEFAULT_PAYLOAD_SIZE,
            // surb_material: None,
        }
    }
}
