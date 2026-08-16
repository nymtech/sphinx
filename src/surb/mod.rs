use crate::constants::{NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SEED_SIZE, PAYLOAD_KEY_SIZE};
use crate::header::delays::Delay;
use crate::payload::key::{PayloadKey, PayloadKeySeed};
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::version::Version;
use crate::{header, SphinxPacket};
use crate::{Error, ErrorKind, Result};
use header::{SphinxHeader, HEADER_SIZE};
use std::fmt;
use x25519_dalek::StaticSecret;

// legacy compatibility wrapper
//
// A SURB only ever carries a single payload key/seed: the one used to add the innermost
// (first-applied) layer of payload encryption, corresponding to the last hop of the SURB's
// route. The remaining layers are added by ordinary mix node hop processing as the packet
// transits the network, and only the SURB's original creator - who retains every derived key
// locally - can remove them all again.
#[derive(Debug)]
enum PayloadKeyMaterial {
    DerivedKey(PayloadKey),
    KeySeed(PayloadKeySeed),
}

impl PayloadKeyMaterial {
    fn from_bytes(bytes: &[u8]) -> Result<PayloadKeyMaterial> {
        // payload key and key seed have distinct, fixed sizes, so the length alone
        // unambiguously tells us which variant we're looking at
        if bytes.len() == PAYLOAD_KEY_SEED_SIZE {
            let mut seed = [0u8; PAYLOAD_KEY_SEED_SIZE];
            seed.copy_from_slice(bytes);
            Ok(PayloadKeyMaterial::KeySeed(seed))
        } else if bytes.len() == PAYLOAD_KEY_SIZE {
            let mut key = [0u8; PAYLOAD_KEY_SIZE];
            key.copy_from_slice(bytes);
            Ok(PayloadKeyMaterial::DerivedKey(key))
        } else {
            Err(Error::new(
                ErrorKind::InvalidSURB,
                "bytes of invalid length provided",
            ))
        }
    }
}

/// A Single Use Reply Block (SURB) must have a pre-aggregated Sphinx header,
/// the address of the first hop in the route of the SURB, and the key material
/// used to add the first (innermost) layer of payload encryption.
///
/// Note that this is deliberately only a single key/seed, not one per hop: the entity using
/// the SURB must not be able to compute every layer of payload encryption itself, since doing
/// so - combined with collusion with the last node on the SURB's route - would let it identify
/// who the reply is being forwarded to.
#[allow(non_snake_case)]
pub struct SURB {
    SURB_header: header::SphinxHeader,
    first_hop_address: NodeAddressBytes,
    payload_key_material: PayloadKeyMaterial,
}

impl fmt::Debug for SURB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SURB")
            .field("SURB_header", &self.SURB_header)
            .field("first_hop_address", &self.first_hop_address)
            .field("payload_key_material", &self.payload_key_material)
            .finish()
    }
}

pub struct SURBMaterial {
    surb_route: Vec<Node>,
    surb_delays: Vec<Delay>,
    surb_destination: Destination,
    version: Version,
}

impl SURBMaterial {
    pub fn new(route: Vec<Node>, delays: Vec<Delay>, destination: Destination) -> Self {
        SURBMaterial {
            surb_route: route,
            surb_delays: delays,
            surb_destination: destination,
            version: Default::default(),
        }
    }

    #[allow(non_snake_case)]
    pub fn construct_SURB(self) -> Result<SURB> {
        let surb_initial_secret = StaticSecret::random();
        SURB::new(surb_initial_secret, self)
    }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }
}

#[allow(non_snake_case)]
impl SURB {
    pub fn new(surb_initial_secret: StaticSecret, surb_material: SURBMaterial) -> Result<Self> {
        let surb_route = surb_material.surb_route;
        let surb_delays = surb_material.surb_delays;
        let surb_destination = surb_material.surb_destination;

        /* Pre-computes the header of the Sphinx packet which will be used as SURB
        and encapsulates it into struct together with the address of the first hop in the route of the SURB, and the key material
        which should be used to layer encrypt the payload. */
        let Some(first_hop) = surb_route.first() else {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "tried to create SURB for an empty route",
            ));
        };

        if surb_route.len() != surb_delays.len() {
            return Err(Error::new(ErrorKind::InvalidSURB, format!("creating SURB for contradictory data: route has len {} while there are {} delays generated", surb_route.len(), surb_delays.len())));
        }

        #[allow(deprecated)]
        let built_header = header::SphinxHeader::new_versioned(
            &surb_initial_secret,
            &surb_route,
            &surb_delays,
            &surb_destination,
            surb_material.version,
        );

        if surb_material.version.expects_legacy_full_payload_keys() {
            Ok(SURB {
                first_hop_address: first_hop.address,
                payload_key_material: PayloadKeyMaterial::DerivedKey(
                    built_header.legacy_first_layer_payload_key(),
                ),
                SURB_header: built_header.into_header(),
            })
        } else {
            Ok(SURB {
                first_hop_address: first_hop.address,
                payload_key_material: PayloadKeyMaterial::KeySeed(
                    built_header.first_layer_payload_key_seed(),
                ),
                SURB_header: built_header.into_header(),
            })
        }
    }

    /// Function takes the precomputed surb header, adds the single, first (innermost) layer of
    /// encryption to the plaintext payload content using the precomputed payload key material,
    /// and returns the full Sphinx packet together with the address of first hop to which it
    /// should be forwarded.
    ///
    /// The remaining layers of encryption are added by each mix node along the SURB's route as
    /// it is forwarded, exactly as happens with the header - this function must never be given
    /// (nor does it have access to) more than the single innermost payload key/seed, since the
    /// caller must not be able to compute what the payload looks like at every hop.
    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        payload_size: usize,
    ) -> Result<(SphinxPacket, NodeAddressBytes)> {
        let header = self.SURB_header;

        // Note that Payload::encapsulate_message performs checks to verify whether the plaintext
        // is going to fit in the packet.
        let payload = match self.payload_key_material {
            PayloadKeyMaterial::DerivedKey(key) => {
                Payload::encapsulate_message(plaintext_message, &[key], payload_size)?
            }
            PayloadKeyMaterial::KeySeed(seed) => {
                Payload::encapsulate_message(plaintext_message, &[seed], payload_size)?
            }
        };

        Ok((SphinxPacket { header, payload }, self.first_hop_address))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let initial_bytes = self
            .SURB_header
            .to_bytes()
            .into_iter()
            .chain(self.first_hop_address.to_bytes());

        match &self.payload_key_material {
            PayloadKeyMaterial::DerivedKey(key) => {
                initial_bytes.chain(key.iter().copied()).collect()
            }
            PayloadKeyMaterial::KeySeed(seed) => {
                initial_bytes.chain(seed.iter().copied()).collect()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // SURB needs to contain exactly a single payload key (or seed)
        if bytes.len() < HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SEED_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "not enough bytes provided to try to recover a SURB",
            ));
        }

        let header_bytes = &bytes[..HEADER_SIZE];
        let first_hop_bytes = &bytes[HEADER_SIZE..HEADER_SIZE + NODE_ADDRESS_LENGTH];
        let payload_key_material_bytes = &bytes[HEADER_SIZE + NODE_ADDRESS_LENGTH..];

        let SURB_header = SphinxHeader::from_bytes(header_bytes)?;
        let first_hop_address = NodeAddressBytes::try_from_byte_slice(first_hop_bytes)?;
        let payload_key_material = PayloadKeyMaterial::from_bytes(payload_key_material_bytes)?;

        Ok(SURB {
            SURB_header,
            first_hop_address,
            payload_key_material,
        })
    }

    pub fn first_hop(&self) -> NodeAddressBytes {
        self.first_hop_address
    }

    pub fn uses_key_seeds(&self) -> bool {
        matches!(self.payload_key_material, PayloadKeyMaterial::KeySeed(_))
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::header::{delays, HEADER_SIZE};
    use crate::version::{PAYLOAD_KEYS_SEEDS_VERSION, X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION};
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE,
        test_utils::fixtures::{destination_fixture, keygen},
    };
    use std::time::Duration;

    fn surb_material_fixture() -> SURBMaterial {
        let (_, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (_, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        SURBMaterial::new(surb_route, surb_delays, surb_destination)
    }

    #[allow(non_snake_case)]
    fn legacy_SURB_fixture() -> SURB {
        let surb_initial_secret = StaticSecret::random();
        let surb_material =
            surb_material_fixture().with_version(X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION);

        SURB::new(surb_initial_secret, surb_material).unwrap()
    }

    #[allow(non_snake_case)]
    fn seeded_SURB_fixture() -> SURB {
        let surb_initial_secret = StaticSecret::random();
        let surb_material = surb_material_fixture().with_version(PAYLOAD_KEYS_SEEDS_VERSION);

        SURB::new(surb_initial_secret, surb_material).unwrap()
    }

    #[test]
    fn returns_error_if_surb_route_empty() {
        let surb_route = Vec::new();
        let surb_destination = destination_fixture();
        let surb_initial_secret = StaticSecret::random();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let expected = ErrorKind::InvalidSURB;

        match SURB::new(
            surb_initial_secret,
            SURBMaterial::new(surb_route, surb_delays, surb_destination),
        ) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when route empty"),
        };
    }

    #[test]
    fn surb_header_has_correct_length() {
        let pre_surb = legacy_SURB_fixture();
        assert_eq!(pre_surb.SURB_header.to_bytes().len(), HEADER_SIZE);
    }

    #[test]
    fn to_bytes_returns_correct_value() {
        let pre_surb = legacy_SURB_fixture();
        let PayloadKeyMaterial::DerivedKey(key) = &pre_surb.payload_key_material else {
            unreachable!()
        };

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            key.to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);

        let pre_surb = seeded_SURB_fixture();
        let PayloadKeyMaterial::KeySeed(seed) = &pre_surb.payload_key_material else {
            unreachable!()
        };

        let pre_surb_bytes = pre_surb.to_bytes();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            seed.to_vec(),
        ]
        .concat();
        assert_eq!(pre_surb_bytes, expected);
    }

    #[test]
    fn only_carries_a_single_payload_key_regardless_of_route_length() {
        // a SURB must never hand out more than the single, innermost payload key/seed - even
        // when routed through the maximum number of hops - otherwise whoever uses it could
        // precompute every layer of payload encryption itself
        let pre_surb = legacy_SURB_fixture();
        let PayloadKeyMaterial::DerivedKey(_) = &pre_surb.payload_key_material else {
            unreachable!()
        };
        assert_eq!(
            pre_surb.to_bytes().len(),
            HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SIZE
        );

        let pre_surb = seeded_SURB_fixture();
        let PayloadKeyMaterial::KeySeed(_) = &pre_surb.payload_key_material else {
            unreachable!()
        };
        assert_eq!(
            pre_surb.to_bytes().len(),
            HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SEED_SIZE
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn embedded_key_is_the_last_hops_key_and_use_surb_adds_exactly_one_layer() {
        use crate::header::keys::KeyMaterial;

        let (_, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (_, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };
        let route = vec![node1, node2, node3];
        let destination = destination_fixture();
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_secs(3));
        let initial_secret = StaticSecret::random();

        // independently derive every hop's key material, so we can pin down exactly which
        // hop's key ends up inside the SURB
        let key_material = KeyMaterial::derive(&route, &initial_secret);
        let expected_key = *key_material
            .expanded_shared_secrets
            .last()
            .unwrap()
            .legacy_payload_key();
        let first_hop_key = *key_material.expanded_shared_secrets[0].legacy_payload_key();
        assert_ne!(
            expected_key, first_hop_key,
            "test fixture produced colliding keys, cannot distinguish hops"
        );

        let surb_material = SURBMaterial::new(route, delays, destination)
            .with_version(X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION);
        let surb = SURB::new(initial_secret, surb_material).unwrap();

        let PayloadKeyMaterial::DerivedKey(surb_key) = &surb.payload_key_material else {
            unreachable!()
        };
        // the SURB must carry the *last* hop's key (the innermost layer), never the first hop's
        assert_eq!(*surb_key, expected_key);

        let message = b"reply to the anonymous sender".to_vec();
        let (packet, _first_hop) = surb.use_surb(&message, DEFAULT_PAYLOAD_SIZE).unwrap();

        // exactly one layer was added: removing it with that single key must fully recover the
        // plaintext, proving there are no further layers left underneath for the SURB user to
        // have computed themselves
        let recovered = packet
            .payload
            .unwrap(expected_key)
            .unwrap()
            .recover_plaintext()
            .unwrap();
        assert_eq!(recovered, message);
    }

    #[test]
    fn returns_error_is_payload_too_large() {
        let pre_surb = legacy_SURB_fixture();
        let plaintext_message = vec![42u8; 5000];
        let expected = ErrorKind::InvalidPayload;

        match SURB::use_surb(pre_surb, &plaintext_message, DEFAULT_PAYLOAD_SIZE) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes_with_legacy_keys() {
        let dummy_SURB = legacy_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );

        let PayloadKeyMaterial::DerivedKey(original_key) = &dummy_SURB.payload_key_material else {
            unreachable!()
        };

        let PayloadKeyMaterial::DerivedKey(recovered_key) = &recovered_SURB.payload_key_material
        else {
            unreachable!()
        };

        assert_eq!(original_key, recovered_key);

        // TODO: saner way of comparing headers...
        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes_with_key_seeds() {
        let dummy_SURB = seeded_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );

        let PayloadKeyMaterial::KeySeed(original_seed) = &dummy_SURB.payload_key_material else {
            unreachable!()
        };

        let PayloadKeyMaterial::KeySeed(recovered_seed) = &recovered_SURB.payload_key_material
        else {
            unreachable!()
        };

        assert_eq!(original_seed, recovered_seed);

        // TODO: saner way of comparing headers...
        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            dummy_SURB.SURB_header.to_bytes()
        );
    }
}
