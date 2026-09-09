//! The initial credential-profile registry of specification Section 13.2.
//!
//! The names reserve design space; the card-specific payload schemas need a
//! separate reviewed profile specification, so this module carries only
//! what the core protocol requires of a profile: its name and whether its
//! actions culminate in a consequential credential command.

pub use refineid_rapp::ProfileName;

/// Inspect supported card and retry state. No consequential command.
pub const PROFILE_CARD_STATUS: &str = "fi.refineid.card-status.v1";
/// Browser or application authentication: PIN 1 verify and key operation.
pub const PROFILE_AUTHENTICATION: &str = "fi.refineid.authentication.v1";
/// Sign a document digest: PIN 2 verify and key operation.
pub const PROFILE_DOCUMENT_SIGNING: &str = "fi.refineid.document-signing.v1";

/// Whether a registered profile defines a consequential credential command.
///
/// A profile without one omits prepare and commit: the proxy answers the
/// request directly after validation, consent, and safe reads (Section
/// 12.2). An unregistered profile is treated as consequential, which only
/// adds protocol steps and can never skip a commit boundary.
#[must_use]
pub fn has_consequential_command(profile: &str) -> bool {
    ProfileName::parse(profile) != Some(ProfileName::CardStatus)
}

#[cfg(test)]
mod tests {
    use super::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, has_consequential_command};

    #[test]
    fn only_card_status_omits_the_commit_boundary() {
        assert!(!has_consequential_command(PROFILE_CARD_STATUS));
        assert!(has_consequential_command(PROFILE_AUTHENTICATION));
        assert!(has_consequential_command("fi.example.unregistered.v1"));
    }
}
