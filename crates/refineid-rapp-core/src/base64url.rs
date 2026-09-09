//! Base64url without padding, RFC 4648 Section 5, for the `rapp:` offer URI.
//!
//! The decoder is strict: padding characters, characters outside the
//! alphabet, and non-canonical trailing bits are rejected rather than
//! tolerated, so exactly one text form exists for any byte string.

/// The 64-character URL-safe alphabet in value order.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Bits carried per base64 character.
const BITS_PER_CHARACTER: u32 = 6;
/// Bits carried per octet.
const BITS_PER_OCTET: u32 = 8;

/// Why a text form is not canonical unpadded base64url.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64UrlError {
    /// A character outside the URL-safe alphabet, including `=` padding.
    InvalidCharacter,
    /// A length of 1 modulo 4, which no byte string produces.
    InvalidLength,
    /// Unused trailing bits were not zero.
    NonCanonicalTrailing,
}

/// Encodes bytes as unpadded base64url text.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        accumulator = (accumulator << BITS_PER_OCTET) | u32::from(*byte);
        bits += BITS_PER_OCTET;
        while bits >= BITS_PER_CHARACTER {
            bits -= BITS_PER_CHARACTER;
            let index = (accumulator >> bits) & 0x3F;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    if bits > 0 {
        let index = (accumulator << (BITS_PER_CHARACTER - bits)) & 0x3F;
        out.push(char::from(ALPHABET[index as usize]));
    }
    out
}

/// Decodes canonical unpadded base64url text.
///
/// # Errors
///
/// Fails on any character outside the alphabet, an impossible length, or
/// nonzero unused trailing bits.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64UrlError> {
    if text.len() % 4 == 1 {
        return Err(Base64UrlError::InvalidLength);
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for character in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|entry| *entry == character)
            .ok_or(Base64UrlError::InvalidCharacter)?;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "an alphabet index is below 64"
        )]
        {
            accumulator = (accumulator << BITS_PER_CHARACTER) | value as u32;
        }
        bits += BITS_PER_CHARACTER;
        if bits >= BITS_PER_OCTET {
            bits -= BITS_PER_OCTET;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "exactly eight masked bits are taken"
            )]
            out.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }
    if bits > 0 && (accumulator & ((1 << bits) - 1)) != 0 {
        return Err(Base64UrlError::NonCanonicalTrailing);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test vectors are constructed to be infallible"
)]
mod tests {
    use super::{Base64UrlError, decode, encode};

    #[test]
    fn rfc4648_vectors_round_trip() {
        for (raw, text) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg"),
            (&b"fooba"[..], "Zm9vYmE"),
            (&b"foobar"[..], "Zm9vYmFy"),
        ] {
            assert_eq!(encode(raw), text);
            assert_eq!(decode(text).unwrap(), raw);
        }
    }

    #[test]
    fn url_safe_characters_are_used() {
        assert_eq!(encode(&[0xFB, 0xFF]), "-_8");
        assert_eq!(decode("-_8").unwrap(), [0xFB, 0xFF]);
    }

    #[test]
    fn padding_and_foreign_characters_are_rejected() {
        assert_eq!(decode("Zg=="), Err(Base64UrlError::InvalidCharacter));
        assert_eq!(decode("Zm9v+g"), Err(Base64UrlError::InvalidCharacter));
    }

    #[test]
    fn impossible_length_is_rejected() {
        assert_eq!(decode("Z"), Err(Base64UrlError::InvalidLength));
    }

    #[test]
    fn non_canonical_trailing_bits_are_rejected() {
        // "Zh" ends with nonzero unused bits; only "Zg" encodes 0x66.
        assert_eq!(decode("Zh"), Err(Base64UrlError::NonCanonicalTrailing));
    }
}
