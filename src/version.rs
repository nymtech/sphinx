// Copyright 2025 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// in the old versions of the sphinx crate we've been attempting to use semver information
// reduced to 3 bytes, where [0, 1, 0] and [0, 1, 1] have already been released.
// therefore those are our starting point for further versioning

use crate::constants::VERSION_LENGTH;

pub const INITIAL_LEGACY_VERSION: Version = Version(1);
pub const UPDATED_LEGACY_VERSION: Version = Version(257);
pub const X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION: Version = Version(258);
pub const PAYLOAD_KEYS_SEEDS_VERSION: Version = Version(259);
/// SURBs created for this version hand out only the *last* hop's payload key seed. The reply's
/// sender adds a single layer of payload encryption; every hop, the final one included,
/// removes one; and only the SURB's creator - holding a [`crate::surb::SurbReplyRecovery`] -
/// can undo the hops' work and recover the plaintext. The creator is therefore the route's
/// final hop. Hop processing is otherwise identical to [`PAYLOAD_KEYS_SEEDS_VERSION`].
pub const SINGLE_SEED_SURB_VERSION: Version = Version(260);

pub const CURRENT_VERSION: Version = SINGLE_SEED_SURB_VERSION;

pub const KNOWN_VERSIONS: &[Version] = &[
    INITIAL_LEGACY_VERSION,
    UPDATED_LEGACY_VERSION,
    X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION,
    PAYLOAD_KEYS_SEEDS_VERSION,
    SINGLE_SEED_SURB_VERSION,
];

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Version(pub u16);

impl Version {
    pub fn new(value: u16) -> Version {
        Version(value)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub fn is_legacy(&self) -> bool {
        self == &INITIAL_LEGACY_VERSION || self == &UPDATED_LEGACY_VERSION
    }

    // as opposed to using payload key seed to derive the keys
    pub fn expects_legacy_full_payload_keys(&self) -> bool {
        self.is_legacy() || self == &X25519_WITH_EXPLICIT_PAYLOAD_KEYS_VERSION
    }

    /// Whether SURBs of this version carry a single (last-hop) payload key seed and require
    /// [`crate::surb::SurbReplyRecovery`] on the receiving side.
    pub fn uses_single_seed_surb(&self) -> bool {
        self == &SINGLE_SEED_SURB_VERSION
    }

    // extra byte comes from the legacy interpretation
    pub fn from_bytes(bytes: [u8; VERSION_LENGTH]) -> Version {
        debug_assert_eq!(bytes[0], 0);
        Version(u16::from_be_bytes([bytes[1], bytes[2]]))
    }

    pub fn to_bytes(self) -> [u8; VERSION_LENGTH] {
        let b = self.0.to_be_bytes();
        [0, b[0], b[1]]
    }
}

impl Default for Version {
    fn default() -> Self {
        CURRENT_VERSION
    }
}

#[cfg(test)]
mod single_seed_surb_version {
    use super::*;

    #[test]
    fn is_260_and_newer_than_the_seeded_version() {
        assert_eq!(260, SINGLE_SEED_SURB_VERSION.value());
        assert!(SINGLE_SEED_SURB_VERSION.value() > PAYLOAD_KEYS_SEEDS_VERSION.value());
    }

    #[test]
    fn is_the_current_and_default_version() {
        assert_eq!(SINGLE_SEED_SURB_VERSION, CURRENT_VERSION);
        assert_eq!(CURRENT_VERSION, Version::default());
    }

    #[test]
    fn is_known_and_processed_like_a_seeded_version() {
        assert!(KNOWN_VERSIONS.contains(&SINGLE_SEED_SURB_VERSION));
        assert!(SINGLE_SEED_SURB_VERSION.uses_single_seed_surb());
        assert!(!SINGLE_SEED_SURB_VERSION.is_legacy());
        // hops derive the payload key from the seed exactly as for 259
        assert!(!SINGLE_SEED_SURB_VERSION.expects_legacy_full_payload_keys());
    }

    #[test]
    fn only_260_uses_a_single_seed() {
        for version in KNOWN_VERSIONS {
            assert_eq!(
                *version == SINGLE_SEED_SURB_VERSION,
                version.uses_single_seed_surb()
            );
        }
    }

    #[test]
    fn roundtrips_through_bytes() {
        let bytes = SINGLE_SEED_SURB_VERSION.to_bytes();
        assert_eq!(SINGLE_SEED_SURB_VERSION, Version::from_bytes(bytes));
    }
}
