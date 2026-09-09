//! The closed action registry of specification Section 13.2.1.
//!
//! Every remote card operation is one of these typed values. The registry
//! carries the payload schemas, the digest-length and key-compatibility
//! invariants, and the result schemas, so no raw request or result map
//! crosses the crate boundary. Documents and unhashed browser input never
//! enter RAPP; the requester supplies digests and registry names only.

use crate::cbor::Value;
use crate::limits::MAX_TEXT_SIZE;
use crate::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING};

/// Ordered wire map used for request context and payload.
pub type WireMap = Vec<(String, Value)>;

/// SHA-224 digest length in bytes.
const DIGEST_SHA224: usize = 28;
/// SHA-256 digest length in bytes.
const DIGEST_SHA256: usize = 32;
/// SHA-384 digest length in bytes.
const DIGEST_SHA384: usize = 48;
/// SHA-512 digest length in bytes.
const DIGEST_SHA512: usize = 64;

/// Certificate selected for a public-data read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateKind {
    /// The authentication certificate associated with PIN 1.
    Authentication,
    /// The qualified-signature certificate associated with PIN 2.
    Signature,
    /// The on-card issuing root CA certificate (EF.4334).
    RootCa,
    /// The on-card issuing intermediate CA certificate (EF.4336).
    IntermediateCa,
}

impl CertificateKind {
    /// The registered wire text of the kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Signature => "signature",
            Self::RootCa => "root_ca",
            Self::IntermediateCa => "intermediate_ca",
        }
    }
}

/// The closed public-key profile registry (Section 13.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProfile {
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 3072-bit.
    Rsa3072,
}

impl KeyProfile {
    /// The registered wire text of the profile.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa_p256",
            Self::EcdsaP384 => "ecdsa_p384",
            Self::Rsa2048 => "rsa_2048",
            Self::Rsa3072 => "rsa_3072",
        }
    }
}

/// The closed signature-algorithm registry (Section 13.2.1). A digest family
/// alone is insufficient: PKCS #1, PSS, and ECDSA are distinct card commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA over a SHA-224 digest.
    EcdsaSha224,
    /// ECDSA over a SHA-256 digest.
    EcdsaSha256,
    /// ECDSA over a SHA-384 digest.
    EcdsaSha384,
    /// ECDSA over a SHA-512 digest.
    EcdsaSha512,
    /// RSA PKCS #1 v1.5 over a SHA-256 digest.
    RsaPkcs1Sha256,
    /// RSA PKCS #1 v1.5 over a SHA-384 digest.
    RsaPkcs1Sha384,
    /// RSA PKCS #1 v1.5 over a SHA-512 digest.
    RsaPkcs1Sha512,
    /// RSA PSS over a SHA-256 digest.
    RsaPssSha256,
}

impl SignatureAlgorithm {
    /// The registered wire text of the algorithm.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EcdsaSha224 => "ecdsa_sha224",
            Self::EcdsaSha256 => "ecdsa_sha256",
            Self::EcdsaSha384 => "ecdsa_sha384",
            Self::EcdsaSha512 => "ecdsa_sha512",
            Self::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            Self::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            Self::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
            Self::RsaPssSha256 => "rsa_pss_sha256",
        }
    }

    /// The exact digest length the algorithm requires.
    #[must_use]
    pub const fn digest_length(self) -> usize {
        match self {
            Self::EcdsaSha224 => DIGEST_SHA224,
            Self::EcdsaSha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => DIGEST_SHA256,
            Self::EcdsaSha384 | Self::RsaPkcs1Sha384 => DIGEST_SHA384,
            Self::EcdsaSha512 | Self::RsaPkcs1Sha512 => DIGEST_SHA512,
        }
    }

    /// Whether the algorithm is registered for the key profile.
    #[must_use]
    pub const fn supports(self, profile: KeyProfile) -> bool {
        matches!(
            (self, profile),
            (
                Self::EcdsaSha224 | Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512,
                KeyProfile::EcdsaP256 | KeyProfile::EcdsaP384
            ) | (
                Self::RsaPkcs1Sha256
                    | Self::RsaPkcs1Sha384
                    | Self::RsaPkcs1Sha512
                    | Self::RsaPssSha256,
                KeyProfile::Rsa2048 | KeyProfile::Rsa3072
            )
        )
    }
}

/// One typed remote card operation of the closed registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardOperation {
    /// Read activation and retry state without touching a credential.
    InspectCard,
    /// Read the public identity fields.
    ReadIdentity,
    /// Read one public certificate. Owned by the profile whose key the
    /// certificate serves.
    ReadCertificate {
        /// Which certificate to read.
        kind: CertificateKind,
    },
    /// Authenticate a browser challenge after proxy-side consent.
    BrowserAuthenticate {
        /// Relying-party origin shown by the authorizer.
        origin: String,
        /// Expected key profile, independently verified by the proxy.
        key_profile: KeyProfile,
        /// Exact signature algorithm.
        algorithm: SignatureAlgorithm,
        /// Already-hashed challenge of the registered length.
        digest: Vec<u8>,
    },
    /// Sign a document digest after proxy-side consent.
    SignDocument {
        /// Document name shown by the authorizer.
        document_name: String,
        /// Expected key profile, independently verified by the proxy.
        key_profile: KeyProfile,
        /// Exact signature algorithm.
        algorithm: SignatureAlgorithm,
        /// Already-hashed document bytes of the registered length.
        digest: Vec<u8>,
    },
}

impl CardOperation {
    /// The credential profile that owns this action (Section 13.2.1).
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        match self {
            Self::InspectCard
            | Self::ReadIdentity
            | Self::ReadCertificate {
                kind: CertificateKind::RootCa | CertificateKind::IntermediateCa,
            } => PROFILE_CARD_STATUS,
            Self::ReadCertificate {
                kind: CertificateKind::Authentication,
            }
            | Self::BrowserAuthenticate { .. } => PROFILE_AUTHENTICATION,
            Self::ReadCertificate {
                kind: CertificateKind::Signature,
            }
            | Self::SignDocument { .. } => PROFILE_DOCUMENT_SIGNING,
        }
    }

    /// The registered action name.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self {
            Self::InspectCard => "inspect_card",
            Self::ReadIdentity => "read_identity",
            Self::ReadCertificate { .. } => "read_certificate",
            Self::BrowserAuthenticate { .. } => "browser_authenticate",
            Self::SignDocument { .. } => "sign_document",
        }
    }

    /// Whether the action carries a consequential credential command.
    #[must_use]
    pub const fn is_consequential(&self) -> bool {
        matches!(
            self,
            Self::BrowserAuthenticate { .. } | Self::SignDocument { .. }
        )
    }

    /// Validates the invariants and produces the exact wire context and
    /// payload maps.
    ///
    /// # Errors
    ///
    /// Fails on an empty or oversized display text, a digest whose length
    /// is not the algorithm's registered length, or an algorithm the key
    /// profile does not support.
    pub fn wire_parts(&self) -> Result<(WireMap, WireMap), OperationError> {
        self.validate()?;
        let mut context = Vec::new();
        let mut payload = Vec::new();
        match self {
            Self::InspectCard | Self::ReadIdentity => {}
            Self::ReadCertificate { kind } => {
                payload.push(("kind".to_owned(), Value::Text(kind.wire_name().to_owned())));
            }
            Self::BrowserAuthenticate {
                origin,
                key_profile,
                algorithm,
                digest,
            } => {
                context.push(("origin".to_owned(), Value::Text(origin.clone())));
                push_signature_payload(&mut payload, *key_profile, *algorithm, digest);
            }
            Self::SignDocument {
                document_name,
                key_profile,
                algorithm,
                digest,
            } => {
                context.push((
                    "document_name".to_owned(),
                    Value::Text(document_name.clone()),
                ));
                push_signature_payload(&mut payload, *key_profile, *algorithm, digest);
            }
        }
        Ok((context, payload))
    }

    const fn validate(&self) -> Result<(), OperationError> {
        match self {
            Self::InspectCard | Self::ReadIdentity | Self::ReadCertificate { .. } => Ok(()),
            Self::BrowserAuthenticate {
                origin: display,
                key_profile,
                algorithm,
                digest,
            }
            | Self::SignDocument {
                document_name: display,
                key_profile,
                algorithm,
                digest,
            } => {
                if display.is_empty() || display.len() > MAX_TEXT_SIZE {
                    return Err(OperationError::DisplayContext);
                }
                if !algorithm.supports(*key_profile) {
                    return Err(OperationError::IncompatibleAlgorithm);
                }
                if digest.len() != algorithm.digest_length() {
                    return Err(OperationError::DigestLength);
                }
                Ok(())
            }
        }
    }
}

fn push_signature_payload(
    payload: &mut WireMap,
    key_profile: KeyProfile,
    algorithm: SignatureAlgorithm,
    digest: &[u8],
) {
    payload.push((
        "key_profile".to_owned(),
        Value::Text(key_profile.wire_name().to_owned()),
    ));
    payload.push((
        "algorithm".to_owned(),
        Value::Text(algorithm.wire_name().to_owned()),
    ));
    payload.push(("digest".to_owned(), Value::Bytes(digest.to_vec())));
}

/// The typed content of a completed result, by the profile schemas the
/// proxies implement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardOperationResult {
    /// Card activation and counter-safe retry state.
    Inspection {
        /// Whether PIN 1 is still in factory state.
        pin1_factory: bool,
        /// Whether PIN 2 is still in factory state.
        pin2_factory: bool,
        /// Remaining PIN 1 attempts when the proxy discloses them.
        pin1_attempts: Option<u8>,
        /// Remaining PIN 2 attempts when the proxy discloses them.
        pin2_attempts: Option<u8>,
        /// Remaining PUK attempts when the proxy discloses them.
        puk_attempts: Option<u8>,
    },
    /// Public identity fields.
    Identity {
        /// Display name from the card.
        display_name: String,
        /// Personal identifier from the card.
        person_id: String,
    },
    /// One certificate as plain DER.
    Certificate(Vec<u8>),
    /// One raw signature.
    Signature(Vec<u8>),
}

impl CardOperationResult {
    /// Parses a completed result body and requires it to answer the given
    /// operation.
    ///
    /// # Errors
    ///
    /// Fails on an unregistered discriminant, a field outside the schema, a
    /// missing field, or a result kind that does not answer the operation;
    /// each is an authenticated protocol violation at the caller.
    pub fn from_body(operation: &CardOperation, body: WireMap) -> Result<Self, OperationError> {
        let mut fields = Fields { entries: body };
        let result = match fields.take_text("type")?.as_str() {
            "inspection" => Self::Inspection {
                pin1_factory: fields.take_bool("pin1_factory")?,
                pin2_factory: fields.take_bool("pin2_factory")?,
                pin1_attempts: fields.take_optional_attempt("pin1_attempts")?,
                pin2_attempts: fields.take_optional_attempt("pin2_attempts")?,
                puk_attempts: fields.take_optional_attempt("puk_attempts")?,
            },
            "identity" => Self::Identity {
                display_name: fields.take_text("display_name")?,
                person_id: fields.take_text("person_id")?,
            },
            "certificate" => {
                let der = fields.take_bytes("der")?;
                let _card_serial = fields.take_optional_text("card_serial")?;
                Self::Certificate(der)
            }
            "signature" => Self::Signature(fields.take_bytes("bytes")?),
            _ => return Err(OperationError::Schema),
        };
        if !fields.entries.is_empty() {
            return Err(OperationError::Schema);
        }
        let answers = matches!(
            (&result, operation),
            (Self::Inspection { .. }, CardOperation::InspectCard)
                | (Self::Identity { .. }, CardOperation::ReadIdentity)
                | (Self::Certificate(_), CardOperation::ReadCertificate { .. })
                | (
                    Self::Signature(_),
                    CardOperation::BrowserAuthenticate { .. } | CardOperation::SignDocument { .. }
                )
        );
        if !answers {
            return Err(OperationError::Schema);
        }
        Ok(result)
    }
}

/// Ordered result-body fields under strict single-take access.
struct Fields {
    entries: WireMap,
}

impl Fields {
    fn take(&mut self, name: &str) -> Result<Value, OperationError> {
        let index = self
            .entries
            .iter()
            .position(|(key, _)| key == name)
            .ok_or(OperationError::Schema)?;
        Ok(self.entries.remove(index).1)
    }

    fn take_text(&mut self, name: &str) -> Result<String, OperationError> {
        match self.take(name)? {
            Value::Text(value) => Ok(value),
            _ => Err(OperationError::Schema),
        }
    }

    fn take_bytes(&mut self, name: &str) -> Result<Vec<u8>, OperationError> {
        match self.take(name)? {
            Value::Bytes(value) => Ok(value),
            _ => Err(OperationError::Schema),
        }
    }

    fn take_bool(&mut self, name: &str) -> Result<bool, OperationError> {
        match self.take(name)? {
            Value::Bool(value) => Ok(value),
            _ => Err(OperationError::Schema),
        }
    }

    fn take_optional_attempt(&mut self, name: &str) -> Result<Option<u8>, OperationError> {
        match self.take(name)? {
            Value::Null => Ok(None),
            Value::Unsigned(count) => u8::try_from(count)
                .map(Some)
                .map_err(|_| OperationError::Schema),
            _ => Err(OperationError::Schema),
        }
    }

    fn take_optional_text(&mut self, name: &str) -> Result<Option<String>, OperationError> {
        let Some(index) = self.entries.iter().position(|(key, _)| key == name) else {
            return Ok(None);
        };
        match self.entries.remove(index).1 {
            Value::Null => Ok(None),
            Value::Text(value) => Ok(Some(value)),
            _ => Err(OperationError::Schema),
        }
    }
}

/// Why a typed operation or result was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationError {
    /// Display text was empty or exceeded the text bound.
    DisplayContext,
    /// The digest length is not the algorithm's registered length.
    DigestLength,
    /// The algorithm is not registered for the key profile.
    IncompatibleAlgorithm,
    /// A result body violated the profile schema or answered the wrong
    /// operation.
    Schema,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{
        CardOperation, CardOperationResult, CertificateKind, KeyProfile, OperationError,
        SignatureAlgorithm,
    };
    use crate::cbor::Value;
    use crate::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING};

    #[test]
    fn certificate_reads_are_owned_by_the_key_matching_profile() {
        let authentication = CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        };
        let signature = CardOperation::ReadCertificate {
            kind: CertificateKind::Signature,
        };
        let root_ca = CardOperation::ReadCertificate {
            kind: CertificateKind::RootCa,
        };
        let intermediate_ca = CardOperation::ReadCertificate {
            kind: CertificateKind::IntermediateCa,
        };
        assert_eq!(authentication.profile(), PROFILE_AUTHENTICATION);
        assert_eq!(signature.profile(), PROFILE_DOCUMENT_SIGNING);
        assert_eq!(root_ca.profile(), PROFILE_CARD_STATUS);
        assert_eq!(intermediate_ca.profile(), PROFILE_CARD_STATUS);
        assert!(!authentication.is_consequential());
        assert!(!root_ca.is_consequential());
    }

    #[test]
    fn digest_length_and_compatibility_are_enforced() {
        let wrong_length = CardOperation::BrowserAuthenticate {
            origin: "kortti.tunnistautuminen.suomi.fi".into(),
            key_profile: KeyProfile::Rsa3072,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![0x2a; SignatureAlgorithm::RsaPkcs1Sha256.digest_length() - 1],
        };
        assert_eq!(wrong_length.wire_parts(), Err(OperationError::DigestLength));

        let incompatible = CardOperation::SignDocument {
            document_name: "agreement.pdf".into(),
            key_profile: KeyProfile::EcdsaP384,
            algorithm: SignatureAlgorithm::RsaPssSha256,
            digest: vec![0x2a; SignatureAlgorithm::RsaPssSha256.digest_length()],
        };
        assert_eq!(
            incompatible.wire_parts(),
            Err(OperationError::IncompatibleAlgorithm)
        );
    }

    #[test]
    fn signature_wire_parts_carry_the_registered_fields() {
        let operation = CardOperation::BrowserAuthenticate {
            origin: "kortti.tunnistautuminen.suomi.fi".into(),
            key_profile: KeyProfile::EcdsaP384,
            algorithm: SignatureAlgorithm::EcdsaSha384,
            digest: vec![0x2a; SignatureAlgorithm::EcdsaSha384.digest_length()],
        };
        let (context, payload) = operation.wire_parts().unwrap();
        assert_eq!(context.len(), 1);
        assert_eq!(context[0].0, "origin");
        let keys: Vec<&str> = payload.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["key_profile", "algorithm", "digest"]);
    }

    #[test]
    fn result_bodies_parse_by_schema_and_must_answer_the_operation() {
        let body = vec![
            ("type".to_owned(), Value::Text("inspection".into())),
            ("pin1_factory".to_owned(), Value::Bool(false)),
            ("pin2_factory".to_owned(), Value::Bool(false)),
            ("pin1_attempts".to_owned(), Value::Unsigned(5)),
            ("pin2_attempts".to_owned(), Value::Null),
            ("puk_attempts".to_owned(), Value::Null),
        ];
        let result =
            CardOperationResult::from_body(&CardOperation::InspectCard, body.clone()).unwrap();
        assert_eq!(
            result,
            CardOperationResult::Inspection {
                pin1_factory: false,
                pin2_factory: false,
                pin1_attempts: Some(5),
                pin2_attempts: None,
                puk_attempts: None,
            }
        );
        // The same body does not answer an identity read.
        assert_eq!(
            CardOperationResult::from_body(&CardOperation::ReadIdentity, body),
            Err(OperationError::Schema)
        );
    }

    #[test]
    fn unknown_and_extra_result_fields_are_schema_violations() {
        let unknown = vec![("type".to_owned(), Value::Text("apdu".into()))];
        assert_eq!(
            CardOperationResult::from_body(&CardOperation::InspectCard, unknown),
            Err(OperationError::Schema)
        );
        let extra = vec![
            ("type".to_owned(), Value::Text("signature".into())),
            ("bytes".to_owned(), Value::Bytes(vec![0x30])),
            ("trace".to_owned(), Value::Text("forbidden".into())),
        ];
        let operation = CardOperation::BrowserAuthenticate {
            origin: "kortti.tunnistautuminen.suomi.fi".into(),
            key_profile: KeyProfile::Rsa3072,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![0x2a; SignatureAlgorithm::RsaPkcs1Sha256.digest_length()],
        };
        assert_eq!(
            CardOperationResult::from_body(&operation, extra),
            Err(OperationError::Schema)
        );
    }

    #[test]
    fn certificate_result_body_accepts_optional_card_serial() {
        let op = CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        };
        let body_with_serial = vec![
            ("type".to_owned(), Value::Text("certificate".into())),
            ("der".to_owned(), Value::Bytes(vec![0x30, 0x82])),
            ("card_serial".to_owned(), Value::Text("123456".into())),
        ];
        let result = CardOperationResult::from_body(&op, body_with_serial).unwrap();
        assert_eq!(result, CardOperationResult::Certificate(vec![0x30, 0x82]));

        let body_without_serial = vec![
            ("type".to_owned(), Value::Text("certificate".into())),
            ("der".to_owned(), Value::Bytes(vec![0x30, 0x82])),
        ];
        let result2 = CardOperationResult::from_body(&op, body_without_serial).unwrap();
        assert_eq!(result2, CardOperationResult::Certificate(vec![0x30, 0x82]));
    }
}
