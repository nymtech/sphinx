use crate::constants::{IDENTIFIER_LENGTH, MAX_PATH_LENGTH, PAYLOAD_KEY_SEED_SIZE};
use crate::payload::key::{derive_payload_key, PayloadKey, PayloadKeySeed};
use crate::payload::Payload;
use crate::route::SURBIdentifier;
use crate::surb::parse_payload_key_seeds;
use crate::{Error, ErrorKind, Result};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Everything the creator of a [`crate::version::SINGLE_SEED_SURB_VERSION`] SURB needs to
/// recover the plaintext of the reply sent with it: the SURB's identifier (the only thing the
/// recipient can read before unsealing, used to look this up) and one payload key seed per
/// hop of the SURB's route, in route order.
///
/// Keep it private to the SURB's creator - it is exactly the material a SURB user must never
/// have. Persist it with [`Self::to_bytes`] next to the SURB's own reply encryption key, and
/// remove it from storage only once [`Self::recover_plaintext`] has succeeded.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SurbReplyRecovery {
    identifier: SURBIdentifier,
    hop_seeds: Vec<PayloadKeySeed>,
}

impl fmt::Debug for SurbReplyRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SurbReplyRecovery")
            .field("identifier", &self.identifier)
            .field(
                "hop_seeds",
                &format_args!("<{} seed(s) redacted>", self.hop_seeds.len()),
            )
            .finish()
    }
}

impl SurbReplyRecovery {
    pub(crate) fn new(identifier: SURBIdentifier, hop_seeds: Vec<PayloadKeySeed>) -> Result<Self> {
        if hop_seeds.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "reply recovery material requires at least one hop seed",
            ));
        }
        if hop_seeds.len() > MAX_PATH_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                format!(
                    "reply recovery material for {} hops exceeds the maximum route length of {MAX_PATH_LENGTH}",
                    hop_seeds.len()
                ),
            ));
        }
        Ok(SurbReplyRecovery {
            identifier,
            hop_seeds,
        })
    }

    /// The identifier of the SURB this material belongs to; delivered in the clear (to the
    /// final hop only) in the reply's header.
    pub fn identifier(&self) -> &SURBIdentifier {
        &self.identifier
    }

    pub fn num_hops(&self) -> usize {
        self.hop_seeds.len()
    }

    #[cfg(test)]
    pub(crate) fn hop_seeds(&self) -> &[PayloadKeySeed] {
        &self.hop_seeds
    }

    /// Length of [`Self::to_bytes`] for a route of `num_hops` hops.
    pub const fn serialized_len(num_hops: usize) -> usize {
        IDENTIFIER_LENGTH + num_hops * PAYLOAD_KEY_SEED_SIZE
    }

    /// `IDENTIFIER || SEEDS`, seeds in route order.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.identifier
            .iter()
            .copied()
            .chain(self.hop_seeds.iter().flat_map(|seed| seed.iter().copied()))
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::serialized_len(1) {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                format!(
                    "reply recovery material needs at least {} bytes, got {}",
                    Self::serialized_len(1),
                    bytes.len()
                ),
            ));
        }
        let (identifier_bytes, seeds_bytes) = bytes.split_at(IDENTIFIER_LENGTH);
        let mut identifier = [0u8; IDENTIFIER_LENGTH];
        identifier.copy_from_slice(identifier_bytes);
        Self::new(identifier, parse_payload_key_seeds(seeds_bytes)?)
    }

    /// Undoes what the network did to a single-seed SURB reply's payload.
    ///
    /// Every hop of the route - the final one included - *removed* one layer of encryption
    /// with its own key, first hop first. This re-adds those layers in reverse (last hop
    /// first), which leaves exactly the single layer the SURB user added with the last hop's
    /// key, and removes that too. The result is the padded plaintext; pass it to
    /// [`Payload::recover_plaintext`] (or use [`Self::recover_plaintext`]), which also
    /// verifies the padding and thereby detects wrong recovery material.
    pub fn unseal(&self, sealed: Payload) -> Result<Payload> {
        let hop_keys: Zeroizing<Vec<PayloadKey>> =
            Zeroizing::new(self.hop_seeds.iter().map(derive_payload_key).collect());
        let Some(last_hop_key) = hop_keys.last() else {
            return Err(Error::new(
                ErrorKind::InvalidSURB,
                "reply recovery material without any hop seeds",
            ));
        };

        let mut payload = sealed;
        for hop_key in hop_keys.iter().rev() {
            payload = payload.add_encryption_layer(hop_key)?;
        }
        payload.unwrap(last_hop_key)
    }

    /// [`Self::unseal`] followed by [`Payload::recover_plaintext`]. Only remove this recovery
    /// material from storage after this returns `Ok`.
    pub fn recover_plaintext(&self, sealed: Payload) -> Result<Vec<u8>> {
        self.unseal(sealed)?.recover_plaintext()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{IDENTIFIER_LENGTH, MAX_PATH_LENGTH, PAYLOAD_KEY_SEED_SIZE};
    use crate::packet::builder::DEFAULT_PAYLOAD_SIZE;
    use crate::payload::key::{derive_payload_key, PayloadKey};
    use crate::payload::Payload;

    fn seeds(hops: usize) -> Vec<PayloadKeySeed> {
        (0..hops)
            .map(|i| [i as u8 + 1; PAYLOAD_KEY_SEED_SIZE])
            .collect()
    }

    #[test]
    fn requires_between_one_and_max_path_length_hops() {
        assert!(SurbReplyRecovery::new([1u8; IDENTIFIER_LENGTH], seeds(0)).is_err());
        assert!(
            SurbReplyRecovery::new([1u8; IDENTIFIER_LENGTH], seeds(MAX_PATH_LENGTH + 1)).is_err()
        );
        for hops in 1..=MAX_PATH_LENGTH {
            let recovery = SurbReplyRecovery::new([1u8; IDENTIFIER_LENGTH], seeds(hops)).unwrap();
            assert_eq!(hops, recovery.num_hops());
            assert_eq!(&[1u8; IDENTIFIER_LENGTH], recovery.identifier());
        }
    }

    #[test]
    fn roundtrips_through_bytes_for_every_route_length() {
        for hops in 1..=MAX_PATH_LENGTH {
            let recovery = SurbReplyRecovery::new([9u8; IDENTIFIER_LENGTH], seeds(hops)).unwrap();
            let bytes = recovery.to_bytes();
            assert_eq!(SurbReplyRecovery::serialized_len(hops), bytes.len());
            assert_eq!(
                IDENTIFIER_LENGTH + hops * PAYLOAD_KEY_SEED_SIZE,
                bytes.len()
            );
            assert_eq!(&bytes[..IDENTIFIER_LENGTH], &[9u8; IDENTIFIER_LENGTH]);
            let recovered = SurbReplyRecovery::from_bytes(&bytes).unwrap();
            assert_eq!(recovery, recovered);
            assert_eq!(bytes, recovered.to_bytes());
        }
    }

    #[test]
    fn from_bytes_rejects_malformed_input() {
        let valid = SurbReplyRecovery::new([9u8; IDENTIFIER_LENGTH], seeds(2))
            .unwrap()
            .to_bytes();
        assert!(SurbReplyRecovery::from_bytes(&valid[..IDENTIFIER_LENGTH]).is_err());
        assert!(SurbReplyRecovery::from_bytes(&valid[..valid.len() - 1]).is_err());
        assert!(SurbReplyRecovery::from_bytes(&[]).is_err());
        let too_many = [
            vec![9u8; IDENTIFIER_LENGTH],
            vec![1u8; (MAX_PATH_LENGTH + 1) * PAYLOAD_KEY_SEED_SIZE],
        ]
        .concat();
        assert!(SurbReplyRecovery::from_bytes(&too_many).is_err());
    }

    #[test]
    fn debug_output_redacts_the_seeds() {
        let recovery = SurbReplyRecovery::new(
            [1u8; IDENTIFIER_LENGTH],
            vec![[0xAB; PAYLOAD_KEY_SEED_SIZE]],
        )
        .unwrap();
        let debug = format!("{recovery:?}");
        assert!(debug.contains("SurbReplyRecovery"), "{debug}");
        assert!(!debug.contains("171"), "seed byte leaked: {debug}");
        assert!(!debug.contains("0xab"), "seed byte leaked: {debug}");
    }

    /// What the network does to a single-seed SURB reply, without headers: the SURB user adds
    /// one layer with the last hop's seed, then every hop (first to last) removes one layer
    /// with its own key.
    fn simulate_reply_transit(recovery: &SurbReplyRecovery, message: &[u8]) -> Payload {
        let last_seed = *recovery.hop_seeds().last().unwrap();
        let mut payload =
            Payload::encapsulate_message(message, &[last_seed], DEFAULT_PAYLOAD_SIZE).unwrap();
        for seed in recovery.hop_seeds() {
            let hop_key: PayloadKey = derive_payload_key(seed);
            payload = payload.unwrap(hop_key).unwrap();
        }
        payload
    }

    #[test]
    fn recovers_the_plaintext_for_every_route_length() {
        let message = vec![42u8; 160];
        for hops in 1..=MAX_PATH_LENGTH {
            let recovery = SurbReplyRecovery::new([3u8; IDENTIFIER_LENGTH], seeds(hops)).unwrap();
            let sealed = simulate_reply_transit(&recovery, &message);
            assert_eq!(
                message,
                recovery.recover_plaintext(sealed).unwrap(),
                "{hops} hops"
            );
        }
    }

    #[test]
    fn the_sealed_payload_is_not_a_valid_plaintext_payload_on_its_own() {
        let recovery = SurbReplyRecovery::new([3u8; IDENTIFIER_LENGTH], seeds(4)).unwrap();
        let sealed = simulate_reply_transit(&recovery, &[42u8; 160]);
        assert!(sealed.recover_plaintext().is_err());
    }

    #[test]
    fn rejects_material_for_a_different_surb() {
        let creator = SurbReplyRecovery::new([3u8; IDENTIFIER_LENGTH], seeds(4)).unwrap();
        let other: Vec<PayloadKeySeed> = (0..4)
            .map(|i| [0xF0 | i as u8; PAYLOAD_KEY_SEED_SIZE])
            .collect();
        let impostor = SurbReplyRecovery::new([3u8; IDENTIFIER_LENGTH], other).unwrap();
        let sealed = simulate_reply_transit(&creator, &[42u8; 160]);
        assert!(impostor.recover_plaintext(sealed).is_err());
    }

    #[test]
    fn rejects_a_payload_that_was_never_sealed() {
        let recovery = SurbReplyRecovery::new([3u8; IDENTIFIER_LENGTH], seeds(4)).unwrap();
        let no_keys: [PayloadKeySeed; 0] = [];
        let plain =
            Payload::encapsulate_message(&[42u8; 160], &no_keys, DEFAULT_PAYLOAD_SIZE).unwrap();
        assert!(recovery.recover_plaintext(plain).is_err());
    }
}
