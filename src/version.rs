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
pub const CURRENT_VERSION: Version = Version(258);

pub const KNOWN_VERSIONS: &[Version] = &[
    INITIAL_LEGACY_VERSION,
    UPDATED_LEGACY_VERSION,
    CURRENT_VERSION,
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
