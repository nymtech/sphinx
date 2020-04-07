use crate::constants::{DESTINATION_ADDRESS_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER};
use crate::header::delays::Delay;
use crate::header::keys::PayloadKey;
use crate::header::SphinxError;
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::{crypto, header, SphinxPacket};
use curve25519_dalek::scalar::Scalar;

#[derive(Clone)]
pub struct SURB {
    /// A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
    /// the address of the first hop in the route of the SURB, and the key material
    /// used to layer encrypt the payload.
    pub SURBHeader: header::SphinxHeader,
    pub first_hop_address: NodeAddressBytes,
    pub payload_keys: Vec<PayloadKey>,
}

#[derive(Debug)]
pub enum SURBError {
    IncorrectSURBRoute,
}

impl SURB {
    pub fn new(
        surb_initial_secret: Scalar,
        surb_route: &[Node],
        surb_delays: &[Delay],
        surb_destination: &Destination,
    ) -> Result<Self, SURBError> {
        assert_eq!(surb_route.len(), surb_delays.len());

        let (header, payload_keys) = header::SphinxHeader::new(
            surb_initial_secret,
            surb_route,
            surb_delays,
            surb_destination,
        );

        let first_hop = surb_route.first().ok_or(SURBError::IncorrectSURBRoute)?;

        Ok(SURB {
            SURBHeader: header,
            first_hop_address: first_hop.address.clone(),
            payload_keys: payload_keys,
        })
    }

    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        surb_destination: &Destination,
    ) -> Result<SphinxPacket, SphinxError> {
        let header = self.SURBHeader;

        if plaintext_message.len() + DESTINATION_ADDRESS_LENGTH > PAYLOAD_SIZE - SECURITY_PARAMETER
        {
            return Err(SphinxError::NotEnoughPayload);
        };

        let payload = Payload::encapsulate_message(
            &plaintext_message,
            &self.payload_keys,
            surb_destination.address.clone(),
        )?;

        Ok(SphinxPacket { header, payload })
    }
}
