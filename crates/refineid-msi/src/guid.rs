// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Package identifiers derived from a single authored value.
//!
//! Windows Installer needs several distinct GUIDs whose stability rules
//! differ: a component identity must never change for the same component, a
//! product code must change with every version, and a package code must
//! change with every build. Hand-managing them is the classic source of
//! broken upgrades, so only the upgrade code is authored and the rest are
//! derived from it by RFC 4122 name-based UUIDs. The same inputs therefore
//! always produce the same package.

use core::fmt;

use sha1::{Digest as _, Sha1};

/// A 128-bit identifier in Windows Installer's braced, uppercase form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid([u8; 16]);

/// A GUID could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuidParseError;

impl fmt::Display for GuidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a GUID of the form {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}")
    }
}

impl std::error::Error for GuidParseError {}

impl Guid {
    /// Parses a GUID written with or without surrounding braces.
    ///
    /// # Errors
    ///
    /// Returns an error if the text is not 32 hexadecimal digits grouped
    /// 8-4-4-4-12 by hyphens.
    pub fn parse(text: &str) -> Result<Self, GuidParseError> {
        let trimmed = text.trim().trim_start_matches('{').trim_end_matches('}');
        let groups: Vec<&str> = trimmed.split('-').collect();
        if groups.len() != 5
            || [8, 4, 4, 4, 12]
                .iter()
                .zip(&groups)
                .any(|(width, group)| group.len() != *width)
        {
            return Err(GuidParseError);
        }

        let mut bytes = [0_u8; 16];
        let digits: String = groups.concat();
        for (index, byte) in bytes.iter_mut().enumerate() {
            let pair = digits.get(index * 2..index * 2 + 2).ok_or(GuidParseError)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| GuidParseError)?;
        }
        Ok(Self(bytes))
    }

    /// Derives a stable identifier from this GUID as namespace and `name`.
    ///
    /// This is the RFC 4122 version 5 construction: SHA-1 over the namespace
    /// bytes followed by the name, with the version and variant bits set.
    #[must_use]
    pub fn derive(self, name: &str) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(self.0);
        hasher.update(name.as_bytes());
        let digest = hasher.finalize();

        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-\
             {:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Guid;

    const NAMESPACE: &str = "{DBD5521A-AA2C-45D1-B79C-8535E2C262A5}";

    #[test]
    fn parses_with_and_without_braces() {
        let braced = Guid::parse(NAMESPACE).expect("braced form parses");
        let bare = Guid::parse(NAMESPACE.trim_matches(['{', '}'])).expect("bare form parses");
        assert_eq!(braced, bare);
    }

    #[test]
    fn round_trips_through_display() {
        let guid = Guid::parse(NAMESPACE).expect("parses");
        assert_eq!(guid.to_string(), NAMESPACE);
    }

    #[test]
    fn rejects_malformed_text() {
        for text in [
            "",
            "{}",
            "not-a-guid",
            "{DBD5521A-AA2C-45D1-B79C-8535E2C262A}",
        ] {
            assert!(Guid::parse(text).is_err(), "{text} must be rejected");
        }
    }

    #[test]
    fn derivation_is_stable_and_distinct_per_name() {
        let namespace = Guid::parse(NAMESPACE).expect("parses");
        let first = namespace.derive("MinidriverDll");
        assert_eq!(first, namespace.derive("MinidriverDll"));
        assert_ne!(first, namespace.derive("CalaisRegistration"));
    }

    #[test]
    fn derivation_sets_the_version_and_variant_bits() {
        let derived = Guid::parse(NAMESPACE).expect("parses").derive("anything");
        let text = derived.to_string();
        // Version 5 in the first nibble of the third group, RFC variant in
        // the first nibble of the fourth.
        assert_eq!(&text[15..16], "5", "{text}");
        assert!(
            ['8', '9', 'A', 'B'].contains(&text.as_bytes()[20].into()),
            "{text}"
        );
    }
}
