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

#[derive(Debug, PartialEq)]
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
        /// Precomputes the header of the Sphinx packet which will be used as SURB
        /// and encapsulates it into struct together with the address of the first hop in the route of the SURB, and the key material
        /// which should be used to layer encrypt the payload.
        assert_eq!(surb_route.len(), surb_delays.len());

        let first_hop = surb_route.first().ok_or(SURBError::IncorrectSURBRoute)?;

        let (header, payload_keys) = header::SphinxHeader::new(
            surb_initial_secret,
            surb_route,
            surb_delays,
            surb_destination,
        );

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
    ) -> Result<(SphinxPacket, NodeAddressBytes), SphinxError> {
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

        Ok((SphinxPacket { header, payload }, self.first_hop_address))
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::header::delays;
    use crate::route::destination_fixture;
    use std::time::Duration;

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = [];
        let surb_destination = destination_fixture();
        let surb_initial_secret = crypto::generate_secret();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let expected = SURBError::IncorrectSURBRoute;

        match SURB::new(
            surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
        ) {
            Err(err) => assert_eq!(expected, err),
            _ => panic!("Should have returned an error when packet bytes too long"),
        };
    }
}
