use crate::header::delays::Delay;
use crate::header::keys::PayloadKey;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::{crypto, header};
use curve25519_dalek::scalar::Scalar;

#[derive(Clone)]
pub struct SURB {
    /// A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
    /// the address of the first hop in the route of the SURB, and the key material
    /// used to layer encrypt the payload.
    pub SURBHeader: header::SphinxHeader,
    pub first_hop_address: NodeAddressBytes,
    pub payload_key_material: Vec<PayloadKey>,
}

#[derive(Debug)]
pub enum SURBCreationError {
    IncorrectSURBRoute,
}

impl SURB {
    pub fn new(
        surb_initial_secret: Scalar,
        surb_route: &[Node],
        surb_delays: &[Delay],
        surb_destination: &Destination,
    ) -> Result<Self, SURBCreationError> {
        assert_eq!(surb_route.len(), surb_delays.len());

        let (header, payload_keys) = header::SphinxHeader::new(
            surb_initial_secret,
            surb_route,
            surb_delays,
            surb_destination,
        );

        let first_hop = surb_route
            .first()
            .ok_or(SURBCreationError::IncorrectSURBRoute)?;

        Ok(SURB {
            SURBHeader: header,
            first_hop_address: first_hop.address.clone(),
            payload_key_material: payload_keys,
        })
    }
}
