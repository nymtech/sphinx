use crate::constants::{
    IDENTIFIER_LENGTH, MAX_PATH_LENGTH, NODE_ADDRESS_LENGTH, PAYLOAD_KEY_SEED_SIZE,
};
use crate::header::delays::Delay;
use crate::payload::key::PayloadKeySeed;
use crate::payload::Payload;
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::version::{Version, PAYLOAD_KEYS_SEEDS_VERSION};
use crate::{header, SphinxPacket};
use crate::{Error, ErrorKind, Result};
use header::{BuiltHeader, SphinxHeader, HEADER_SIZE};
use std::fmt;
use x25519_dalek::StaticSecret;

mod recovery;
pub use recovery::SurbReplyRecovery;

/// A Single Use Reply Block (SURB): a pre-computed Sphinx header, the address of the first hop
/// of its route, and the payload key seed(s) whoever uses the SURB must layer-encrypt the
/// payload with.
///
/// Which seeds are present depends on the version the SURB was created for:
/// * [`PAYLOAD_KEYS_SEEDS_VERSION`] (259): one seed per hop. The SURB user adds every layer
///   and the route's last hop recovers the plaintext.
/// * [`crate::version::SINGLE_SEED_SURB_VERSION`] (260): only the last hop's seed. The SURB
///   user adds a single layer and only the SURB's creator, holding the
///   [`SurbReplyRecovery`] returned by [`SURB::new_recoverable`], can recover the plaintext.
///   Handing out every hop's seed would let the SURB user precompute the payload at every hop
///   and, together with any hop that learns the destination, link the reply to its recipient.
#[allow(non_snake_case)]
pub struct SURB {
    SURB_header: SphinxHeader,
    first_hop_address: NodeAddressBytes,
    payload_key_seeds: Vec<PayloadKeySeed>,
}

impl fmt::Debug for SURB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SURB")
            .field("SURB_header", &self.SURB_header)
            .field("first_hop_address", &self.first_hop_address)
            .field(
                "payload_key_seeds",
                &format_args!("<{} seed(s) redacted>", self.payload_key_seeds.len()),
            )
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
    /// The version is deliberately explicit - it decides whether the SURB hands out one seed
    /// per hop (259) or a single seed plus recovery material (260), and a silently changing
    /// default here would change what goes on the wire.
    pub fn new(
        route: Vec<Node>,
        delays: Vec<Delay>,
        destination: Destination,
        version: Version,
    ) -> Self {
        SURBMaterial {
            surb_route: route,
            surb_delays: delays,
            surb_destination: destination,
            version,
        }
    }

    /// Creates a [`PAYLOAD_KEYS_SEEDS_VERSION`] SURB with a fresh random initial secret.
    /// Fails for any other version: single-seed SURBs must go through
    /// [`SURBMaterial::construct_recoverable_SURB`] so that the recovery material is not lost.
    #[allow(non_snake_case)]
    pub fn construct_SURB(self) -> Result<SURB> {
        SURB::new(StaticSecret::random(), self)
    }

    /// Creates a [`crate::version::SINGLE_SEED_SURB_VERSION`] SURB with a fresh random initial
    /// secret, together with the [`SurbReplyRecovery`] its creator needs to read the reply.
    #[allow(non_snake_case)]
    pub fn construct_recoverable_SURB(self) -> Result<(SURB, SurbReplyRecovery)> {
        SURB::new_recoverable(StaticSecret::random(), self)
    }
}

/// Parses `bytes` as a concatenation of payload key seeds: a non-empty multiple of
/// [`PAYLOAD_KEY_SEED_SIZE`] holding at most [`MAX_PATH_LENGTH`] seeds.
pub(crate) fn parse_payload_key_seeds(bytes: &[u8]) -> Result<Vec<PayloadKeySeed>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(PAYLOAD_KEY_SEED_SIZE) {
        return Err(Error::new(
            ErrorKind::InvalidSURB,
            format!(
                "payload key seeds must be a non-empty multiple of {PAYLOAD_KEY_SEED_SIZE} bytes, got {}",
                bytes.len()
            ),
        ));
    }
    let count = bytes.len() / PAYLOAD_KEY_SEED_SIZE;
    if count > MAX_PATH_LENGTH {
        return Err(Error::new(
            ErrorKind::InvalidSURB,
            format!(
                "{count} payload key seeds exceed the maximum route length of {MAX_PATH_LENGTH}"
            ),
        ));
    }
    let (seeds, remainder) = bytes.as_chunks::<PAYLOAD_KEY_SEED_SIZE>();
    // guaranteed by the `is_multiple_of` check above
    debug_assert!(remainder.is_empty());
    Ok(seeds.to_vec())
}

#[allow(non_snake_case)]
impl SURB {
    /// Creates a [`PAYLOAD_KEYS_SEEDS_VERSION`] SURB carrying one payload key seed per hop.
    pub fn new(surb_initial_secret: StaticSecret, surb_material: SURBMaterial) -> Result<Self> {
        let version = surb_material.version;
        if version != PAYLOAD_KEYS_SEEDS_VERSION {
            let reason = if version.uses_single_seed_surb() {
                "single-seed SURBs must be created with SURB::new_recoverable (or SURBMaterial::construct_recoverable_SURB) so their recovery material is not lost"
            } else {
                "SURBs can only be created for PAYLOAD_KEYS_SEEDS_VERSION (259) or SINGLE_SEED_SURB_VERSION (260)"
            };
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                format!("{reason}; requested version {}", version.value()),
            ));
        }

        let (built_header, first_hop_address) =
            Self::build_surb_header(&surb_initial_secret, &surb_material)?;

        Ok(SURB {
            first_hop_address,
            payload_key_seeds: built_header.payload_key_seeds(),
            SURB_header: built_header.into_header(),
        })
    }

    /// Creates a [`crate::version::SINGLE_SEED_SURB_VERSION`] SURB carrying only the last
    /// hop's payload key seed, and the recovery material - every hop's seed - that only the
    /// creator keeps. The creator must be the route's final hop.
    ///
    /// The destination's identifier must be non-zero: it is delivered to the final hop in the
    /// clear and is the only thing the recipient can read before unsealing, so it is what the
    /// recovery material is looked up by.
    pub fn new_recoverable(
        surb_initial_secret: StaticSecret,
        surb_material: SURBMaterial,
    ) -> Result<(Self, SurbReplyRecovery)> {
        if !surb_material.version.uses_single_seed_surb() {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                format!(
                    "recoverable SURBs require SINGLE_SEED_SURB_VERSION (260), requested version {}",
                    surb_material.version.value()
                ),
            ));
        }
        if surb_material.surb_destination.identifier == [0u8; IDENTIFIER_LENGTH] {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "single-seed SURBs require a non-zero identifier to look the recovery material up by",
            ));
        }

        let (built_header, first_hop_address) =
            Self::build_surb_header(&surb_initial_secret, &surb_material)?;

        let hop_seeds = built_header.payload_key_seeds();
        let Some(last_hop_seed) = hop_seeds.last().copied() else {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "header was built without any hop secrets",
            ));
        };
        let recovery =
            SurbReplyRecovery::new(surb_material.surb_destination.identifier, hop_seeds)?;

        let surb = SURB {
            first_hop_address,
            payload_key_seeds: vec![last_hop_seed],
            SURB_header: built_header.into_header(),
        };
        Ok((surb, recovery))
    }

    /// Validates the route/delays and pre-computes the Sphinx header the reply will travel
    /// with, returning it together with the address of the first hop.
    fn build_surb_header(
        surb_initial_secret: &StaticSecret,
        surb_material: &SURBMaterial,
    ) -> Result<(BuiltHeader, NodeAddressBytes)> {
        let Some(first_hop) = surb_material.surb_route.first() else {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "tried to create SURB for an empty route",
            ));
        };

        if surb_material.surb_route.len() != surb_material.surb_delays.len() {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                format!(
                    "creating SURB for contradictory data: route has len {} while there are {} delays generated",
                    surb_material.surb_route.len(),
                    surb_material.surb_delays.len()
                ),
            ));
        }

        #[allow(deprecated)]
        let built_header = SphinxHeader::new_versioned(
            surb_initial_secret,
            &surb_material.surb_route,
            &surb_material.surb_delays,
            &surb_material.surb_destination,
            surb_material.version,
        )?;

        Ok((built_header, first_hop.address))
    }

    /// Layer-encrypts `plaintext_message` with the SURB's payload key seed(s) and returns the
    /// full Sphinx packet together with the address of the first hop to forward it to.
    pub fn use_surb(
        self,
        plaintext_message: &[u8],
        payload_size: usize,
    ) -> Result<(SphinxPacket, NodeAddressBytes)> {
        // Payload::encapsulate_message checks that the plaintext fits the payload size
        let payload =
            Payload::encapsulate_message(plaintext_message, &self.payload_key_seeds, payload_size)?;

        Ok((
            SphinxPacket {
                header: self.SURB_header,
                payload,
            },
            self.first_hop_address,
        ))
    }

    /// `HEADER || FIRST_HOP_ADDRESS || SEEDS`, seeds in route order.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.SURB_header
            .to_bytes()
            .into_iter()
            .chain(self.first_hop_address.to_bytes())
            .chain(
                self.payload_key_seeds
                    .iter()
                    .flat_map(|seed| seed.iter().copied()),
            )
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // a SURB carries at least one payload key seed
        if bytes.len() < HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SEED_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "not enough bytes provided to try to recover a SURB",
            ));
        }

        let header_bytes = &bytes[..HEADER_SIZE];
        let first_hop_bytes = &bytes[HEADER_SIZE..HEADER_SIZE + NODE_ADDRESS_LENGTH];
        let seeds_bytes = &bytes[HEADER_SIZE + NODE_ADDRESS_LENGTH..];

        let SURB_header = SphinxHeader::from_bytes(header_bytes)?;
        let first_hop_address = NodeAddressBytes::try_from_byte_slice(first_hop_bytes)?;
        let payload_key_seeds = parse_payload_key_seeds(seeds_bytes)?;

        Ok(SURB {
            SURB_header,
            first_hop_address,
            payload_key_seeds,
        })
    }

    pub fn first_hop(&self) -> NodeAddressBytes {
        self.first_hop_address
    }

    /// Number of payload key seeds carried: the route length for 259 SURBs, `1` for 260 SURBs.
    pub fn materials_count(&self) -> usize {
        self.payload_key_seeds.len()
    }
}

#[cfg(test)]
mod prepare_and_use_process_surb {
    use super::*;
    use crate::constants::NODE_ADDRESS_LENGTH;
    use crate::header::{delays, HEADER_SIZE};
    use crate::version::{
        PAYLOAD_KEYS_SEEDS_VERSION, SINGLE_SEED_SURB_VERSION,
        X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION,
    };
    use crate::{
        packet::builder::DEFAULT_PAYLOAD_SIZE,
        test_utils::fixtures::{destination_fixture, keygen},
    };
    use std::time::Duration;

    fn surb_material_fixture(version: Version) -> SURBMaterial {
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

        SURBMaterial::new(surb_route, surb_delays, surb_destination, version)
    }

    #[allow(non_snake_case)]
    fn seeded_SURB_fixture() -> SURB {
        let surb_material = surb_material_fixture(PAYLOAD_KEYS_SEEDS_VERSION);
        SURB::new(StaticSecret::random(), surb_material).unwrap()
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
            SURBMaterial::new(
                surb_route,
                surb_delays,
                surb_destination,
                PAYLOAD_KEYS_SEEDS_VERSION,
            ),
        ) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when route empty"),
        };
    }

    #[test]
    fn surb_header_has_correct_length() {
        let pre_surb = seeded_SURB_fixture();
        assert_eq!(pre_surb.SURB_header.to_bytes().len(), HEADER_SIZE);
    }

    #[test]
    fn to_bytes_is_header_then_first_hop_then_seeds_in_route_order() {
        let pre_surb = seeded_SURB_fixture();
        let expected = [
            pre_surb.SURB_header.to_bytes(),
            [5u8; NODE_ADDRESS_LENGTH].to_vec(),
            pre_surb.payload_key_seeds.concat(),
        ]
        .concat();
        assert_eq!(expected, pre_surb.to_bytes());
    }

    #[test]
    fn returns_error_is_payload_too_large() {
        let pre_surb = seeded_SURB_fixture();
        let plaintext_message = vec![42u8; 5000];
        let expected = ErrorKind::InvalidPayload;

        match SURB::use_surb(pre_surb, &plaintext_message, DEFAULT_PAYLOAD_SIZE) {
            Err(err) => assert_eq!(expected, err.kind()),
            _ => panic!("Should have returned an error when payload bytes too long"),
        };
    }

    #[test]
    #[allow(non_snake_case)]
    fn can_be_converted_to_and_from_bytes() {
        let dummy_SURB = seeded_SURB_fixture();
        let bytes = dummy_SURB.to_bytes();
        let recovered_SURB = SURB::from_bytes(&bytes).unwrap();

        assert_eq!(
            dummy_SURB.first_hop_address,
            recovered_SURB.first_hop_address
        );
        assert_eq!(
            dummy_SURB.payload_key_seeds,
            recovered_SURB.payload_key_seeds
        );
        assert_eq!(
            dummy_SURB.SURB_header.to_bytes(),
            recovered_SURB.SURB_header.to_bytes()
        );
    }

    #[test]
    fn seeded_surb_carries_one_seed_per_hop() {
        let surb = seeded_SURB_fixture();
        assert_eq!(3, surb.materials_count());
    }

    #[test]
    fn seeded_surb_serialises_exactly_as_0_7_0() {
        let surb = seeded_SURB_fixture();
        let bytes = surb.to_bytes();
        assert_eq!(
            HEADER_SIZE + NODE_ADDRESS_LENGTH + 3 * PAYLOAD_KEY_SEED_SIZE,
            bytes.len()
        );
        let recovered = SURB::from_bytes(&bytes).unwrap();
        assert_eq!(3, recovered.materials_count());
        assert_eq!(bytes, recovered.to_bytes());
    }

    #[test]
    fn explicit_payload_keys_version_can_no_longer_create_surbs() {
        let material = surb_material_fixture(X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION);
        assert!(SURB::new(StaticSecret::random(), material).is_err());
    }

    #[test]
    fn single_seed_version_requires_the_recoverable_constructor() {
        let material = surb_material_fixture(SINGLE_SEED_SURB_VERSION);
        let err = SURB::new(StaticSecret::random(), material).unwrap_err();
        assert!(err.to_string().contains("new_recoverable"), "{err}");
    }

    fn surb_bytes_with_key_material(key_material: &[u8]) -> Vec<u8> {
        let mut bytes = seeded_SURB_fixture().to_bytes();
        bytes.truncate(HEADER_SIZE + NODE_ADDRESS_LENGTH);
        bytes.extend_from_slice(key_material);
        bytes
    }

    #[test]
    fn from_bytes_accepts_every_supported_seed_count() {
        for hops in 1..=crate::constants::MAX_PATH_LENGTH {
            let bytes = surb_bytes_with_key_material(&vec![7u8; hops * PAYLOAD_KEY_SEED_SIZE]);
            assert_eq!(hops, SURB::from_bytes(&bytes).unwrap().materials_count());
        }
    }

    #[test]
    fn from_bytes_rejects_more_seeds_than_the_maximum_path_length() {
        let bytes = surb_bytes_with_key_material(
            &[7u8; (crate::constants::MAX_PATH_LENGTH + 1) * PAYLOAD_KEY_SEED_SIZE],
        );
        assert!(SURB::from_bytes(&bytes).is_err());
    }

    #[test]
    fn from_bytes_rejects_legacy_full_payload_keys() {
        // a single 192-byte key is 12 seeds' worth of bytes - more than any route has hops
        let bytes = surb_bytes_with_key_material(&[7u8; crate::constants::PAYLOAD_KEY_SIZE]);
        assert!(SURB::from_bytes(&bytes).is_err());
    }

    #[test]
    fn from_bytes_rejects_partial_seeds() {
        let bytes = surb_bytes_with_key_material(&[7u8; 3 * PAYLOAD_KEY_SEED_SIZE + 1]);
        assert!(SURB::from_bytes(&bytes).is_err());
        let bytes = surb_bytes_with_key_material(&[]);
        assert!(SURB::from_bytes(&bytes).is_err());
    }

    #[test]
    fn recoverable_surb_carries_only_the_last_hop_seed() {
        let material = surb_material_fixture(SINGLE_SEED_SURB_VERSION);
        let (surb, recovery) = SURB::new_recoverable(StaticSecret::random(), material).unwrap();
        assert_eq!(1, surb.materials_count());
        assert_eq!(3, recovery.num_hops());
        assert_eq!(
            recovery.hop_seeds().last().unwrap(),
            &surb.payload_key_seeds[0]
        );
    }

    #[test]
    fn recoverable_surb_is_filed_under_its_destination_identifier() {
        let material = surb_material_fixture(SINGLE_SEED_SURB_VERSION);
        let expected = material.surb_destination.identifier;
        assert_ne!(
            [0u8; crate::constants::IDENTIFIER_LENGTH],
            expected,
            "fixture must be non-zero"
        );
        let (_, recovery) = SURB::new_recoverable(StaticSecret::random(), material).unwrap();
        assert_eq!(&expected, recovery.identifier());
    }

    #[test]
    fn recoverable_surb_rejects_a_zero_identifier() {
        let mut material = surb_material_fixture(SINGLE_SEED_SURB_VERSION);
        material.surb_destination.identifier = [0u8; crate::constants::IDENTIFIER_LENGTH];
        assert!(SURB::new_recoverable(StaticSecret::random(), material).is_err());
    }

    #[test]
    fn recoverable_surb_rejects_the_seeded_version() {
        let material = surb_material_fixture(PAYLOAD_KEYS_SEEDS_VERSION);
        assert!(SURB::new_recoverable(StaticSecret::random(), material).is_err());
    }

    #[test]
    fn recoverable_surb_serialises_with_a_single_seed() {
        let material = surb_material_fixture(SINGLE_SEED_SURB_VERSION);
        let (surb, _) = material.construct_recoverable_SURB().unwrap();
        let bytes = surb.to_bytes();
        assert_eq!(
            HEADER_SIZE + NODE_ADDRESS_LENGTH + PAYLOAD_KEY_SEED_SIZE,
            bytes.len()
        );
        assert_eq!(1, SURB::from_bytes(&bytes).unwrap().materials_count());
    }

    #[test]
    fn surb_for_a_route_longer_than_max_path_length_is_an_error() {
        let route: Vec<Node> = (0..=crate::constants::MAX_PATH_LENGTH)
            .map(|_| crate::test_utils::random_node())
            .collect();
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_secs(1));
        let material = SURBMaterial::new(
            route,
            delays,
            destination_fixture(),
            PAYLOAD_KEYS_SEEDS_VERSION,
        );
        assert!(material.construct_SURB().is_err());
    }
}
