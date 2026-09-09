//! Protocol identifiers of specification Section 6.
//!
//! Random identifiers come from the operating system's cryptographically
//! secure generator. Derived identifiers are computed by both peers from a
//! completed Noise handshake hash (Section 8.5) and never transmitted by the
//! handshake that creates them. No identifier may derive from a card, person,
//! account, or globally stable device identifier.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bytes in a random offer identifier.
pub const OFFER_ID_LENGTH: usize = 32;
/// Bytes in the random pairing bearer secret.
pub const PAIRING_SECRET_LENGTH: usize = 32;
/// Bytes in a derived pair identifier.
pub const PAIR_ID_LENGTH: usize = 16;
/// Bytes in a derived session identifier.
pub const SESSION_ID_LENGTH: usize = 16;
/// Bytes in a random operation identifier.
pub const OPERATION_ID_LENGTH: usize = 16;
/// Bytes in a derived transport rendezvous token.
pub const RENDEZVOUS_TOKEN_LENGTH: usize = 16;
/// Bytes in a random liveness challenge.
pub const CHALLENGE_LENGTH: usize = 32;

/// Domain-separation prefix for the derived session identifier.
const SESSION_ID_DOMAIN: &[u8] = b"RAPP-session-id-v1";
/// Domain-separation prefix for the derived pair identifier.
const PAIR_ID_DOMAIN: &[u8] = b"RAPP-pair-id-v1";
/// Domain-separation prefix for the derived transport rendezvous token.
const RENDEZVOUS_TOKEN_DOMAIN: &[u8] = b"RAPP-rendezvous-v1";

/// The random-generator failure surfaced by identifier creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomUnavailable;

/// Fills a fixed-size array from the system's secure generator.
fn secure_random<const LENGTH: usize>() -> Result<[u8; LENGTH], RandomUnavailable> {
    let mut bytes = [0u8; LENGTH];
    getrandom::fill(&mut bytes).map_err(|_| RandomUnavailable)?;
    Ok(bytes)
}

/// A random 32-byte identifier scoping one pairing offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfferId(pub [u8; OFFER_ID_LENGTH]);

impl OfferId {
    /// Creates a fresh random offer identifier.
    ///
    /// # Errors
    ///
    /// Fails only when the operating system's generator is unavailable.
    pub fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self(secure_random()?))
    }
}

/// The random 32-byte bearer secret of one pairing offer.
///
/// Section 9.2: never logged, copied, synchronized, backed up, or retained
/// after its use as the handshake pre-shared key ends. The value zeroizes on
/// drop; consuming call sites drop it at the moment the specification names.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret(pub [u8; PAIRING_SECRET_LENGTH]);

impl PairingSecret {
    /// Creates a fresh random bearer secret.
    ///
    /// # Errors
    ///
    /// Fails only when the operating system's generator is unavailable.
    pub fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self(secure_random()?))
    }
}

impl core::fmt::Debug for PairingSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PairingSecret(redacted)")
    }
}

/// The derived 16-byte identifier naming one stored peer relationship.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PairId(pub [u8; PAIR_ID_LENGTH]);

/// The derived 16-byte identifier scoping one authenticated channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionId(pub [u8; SESSION_ID_LENGTH]);

/// The derived 16-byte pair-specific rendezvous token (Section 8.5).
///
/// Transports that must name a pairing on the wire carry this value, never
/// `PairId`; the two are computationally unlinkable without the handshake
/// hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousToken(pub [u8; RENDEZVOUS_TOKEN_LENGTH]);

/// A random 16-byte identifier scoping one semantic operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId(pub [u8; OPERATION_ID_LENGTH]);

impl OperationId {
    /// Creates a fresh random operation identifier.
    ///
    /// # Errors
    ///
    /// Fails only when the operating system's generator is unavailable.
    pub fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self(secure_random()?))
    }
}

/// A random 32-byte liveness challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge(pub [u8; CHALLENGE_LENGTH]);

impl Challenge {
    /// Creates a fresh random challenge.
    ///
    /// # Errors
    ///
    /// Fails only when the operating system's generator is unavailable.
    pub fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self(secure_random()?))
    }
}

/// Derives the first sixteen bytes of a domain-separated SHA-256.
fn derive_sixteen(domain: &[u8], handshake_hash: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(handshake_hash);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Derives the session identifier from a completed handshake hash.
#[must_use]
pub fn derive_session_id(handshake_hash: &[u8]) -> SessionId {
    SessionId(derive_sixteen(SESSION_ID_DOMAIN, handshake_hash))
}

/// Derives the pair identifier from a completed pairing handshake hash.
#[must_use]
pub fn derive_pair_id(handshake_hash: &[u8]) -> PairId {
    PairId(derive_sixteen(PAIR_ID_DOMAIN, handshake_hash))
}

/// Derives the transport rendezvous token from a completed pairing
/// handshake hash.
#[must_use]
pub fn derive_rendezvous_token(handshake_hash: &[u8]) -> RendezvousToken {
    RendezvousToken(derive_sixteen(RENDEZVOUS_TOKEN_DOMAIN, handshake_hash))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test vectors are constructed to be infallible"
)]
mod tests {
    use super::{Challenge, OfferId, OperationId, derive_pair_id, derive_session_id};

    #[test]
    fn derived_identifiers_are_stable_and_domain_separated() {
        let hash = [0x42u8; 32];
        let session = derive_session_id(&hash);
        let pair = derive_pair_id(&hash);
        assert_eq!(session, derive_session_id(&hash));
        assert_eq!(pair, derive_pair_id(&hash));
        assert_ne!(session.0, pair.0);
    }

    #[test]
    fn random_identifiers_differ() {
        assert_ne!(OfferId::random().unwrap(), OfferId::random().unwrap());
        assert_ne!(
            OperationId::random().unwrap(),
            OperationId::random().unwrap()
        );
        assert_ne!(Challenge::random().unwrap(), Challenge::random().unwrap());
    }

    #[test]
    fn pairing_secret_debug_reveals_nothing() {
        let secret = super::PairingSecret([7u8; 32]);
        assert_eq!(format!("{secret:?}"), "PairingSecret(redacted)");
    }
}
