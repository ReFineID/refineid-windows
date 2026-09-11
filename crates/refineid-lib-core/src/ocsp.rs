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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! OCSP request/response codec for revocation checking (RFC 6960).
//!
//! This module owns ASN.1-level codec only:
//!
//! - [`build_request`] produces the DER bytes of an `OCSPRequest`
//!   ready to POST to the responder URL (`Content-Type:
//!   application/ocsp-request`). Needs the issuer's SHA-1 `Name`
//!   hash and `SPKI` hash and the cert's serial -- the hashes are
//!   the caller's responsibility (they live one layer up where
//!   `sha1` is wired in) so this module stays additive-dep-free.
//! - `parse_response` decodes an `OCSPResponse` body into a
//!   structured [`OcspResponse`] with the produced-at timestamp,
//!   producing responder ID hint, and the list of per-cert
//!   statuses.
//!
//! The request side also owns the nonce: [`OcspNonce`] draws the
//! RFC 8954 randomness and [`build_request_with_nonce`] encodes the
//! extension. Out of scope: responder signature verification (trust
//! lives a layer up) and the HTTP transport (lib-core stays HTTP-free
//! per the crate's charter).

use crate::identity::CertSerial;
use crate::oid::known;
use crate::x509::{DateTime, X509Error};
use spki::der::asn1::{AnyRef, ObjectIdentifier};
use spki::der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};
use x509_cert::ext::pkix::CrlReason as X509CrlReason;

/// `id-sha1` OID (`1.3.14.3.2.26`), the default and
/// MUST-support `CertID.hashAlgorithm` per RFC 6960 §4.3.
/// SHA-1 here is a binding identifier over the issuer Name and
/// key, not a security primitive -- a collision would not let
/// an attacker forge responses (the responder also signs over
/// `tbsResponseData`).
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

// The `BasicOCSPResponse` `responseType` (`id-pkix-ocsp-basic`,
// RFC 6960 §4.2.1) is `known::BASIC_OCSP_RESPONSE`; the parser asserts
// it inside the outer `ResponseBytes` wrapper.

// ----- Request side -----

/// The `CertID.issuerNameHash` (RFC 6960 sec.4.1.1).
///
/// SHA-1 of the issuer's DER-encoded `Name`. A distinct type from
/// [`IssuerKeyHash`] so the two same-shaped digests cannot be transposed in
/// a [`build_request`] call: swapping them yields a valid-looking request
/// that silently mis-identifies the cert, and the type makes that a compile
/// error instead.
#[derive(Clone, Copy, Debug)]
pub struct IssuerNameHash([u8; 20]);

/// The `CertID.issuerKeyHash` (RFC 6960 sec.4.1.1).
///
/// SHA-1 of the issuer's `subjectPublicKey` BIT STRING value. The
/// role-distinct sibling of [`IssuerNameHash`]; see that type for why they
/// are not interchangeable.
#[derive(Clone, Copy, Debug)]
pub struct IssuerKeyHash([u8; 20]);

impl IssuerNameHash {
    /// Tag an already-computed SHA-1 digest as the issuer-name hash.
    #[must_use]
    pub const fn new(digest: [u8; 20]) -> Self {
        Self(digest)
    }
}

impl IssuerKeyHash {
    /// Tag an already-computed SHA-1 digest as the issuer-key hash.
    #[must_use]
    pub const fn new(digest: [u8; 20]) -> Self {
        Self(digest)
    }

    /// Compute the issuer-key hash from a typed
    /// [`SubjectPublicKeyInfo`](crate::x509::SpkiDer): SHA-1 over the
    /// `subjectPublicKey` BIT STRING value (RFC 6960 sec.4.1.1). The
    /// raw key material is reached only here and never escapes as a
    /// bare `&[u8]`. Total -- a constructed `SpkiDer` already
    /// validated its envelope, so there is no failure mode.
    #[must_use]
    pub fn from_subject_public_key(spki: &crate::x509::SpkiDer<'_>) -> Self {
        use sha1::Digest as _;
        let mut digest = [0_u8; 20];
        digest.copy_from_slice(&sha1::Sha1::digest(spki.subject_public_key_bits()));
        Self::new(digest)
    }
}

/// A 128-bit OCSP request nonce (RFC 8954).
///
/// Fresh randomness the responder echoes back, so an old signed response
/// can't be replayed. Constructible only from a successful RNG draw via
/// [`OcspNonce::random`], so an all-zero or otherwise unfilled buffer can
/// never reach [`build_request_with_nonce`].
#[derive(Clone, Copy, Debug)]
pub struct OcspNonce([u8; 16]);

impl OcspNonce {
    /// Draw 16 bytes (128 bits -- RFC 8954's minimum) of OS randomness.
    ///
    /// A failed OS RNG means no cryptographic operation on this host can be
    /// trusted, so the caller must propagate the error and abort -- never
    /// drop the nonce and send a replayable request.
    ///
    /// # Errors
    /// Returns [`crate::rng::Failure`] if the OS RNG is unavailable, exactly
    /// like the other RNG draws in this crate ([`crate::aa`],
    /// [`crate::pace`], [`crate::ca`]).
    pub fn random() -> Result<Self, crate::rng::Failure> {
        Ok(Self(crate::rng::array::<16>()?))
    }

    /// The 16 nonce bytes, for matching against the responder's echoed
    /// value (RFC 8954 sec.2.1).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The DER bytes of an `OCSPRequest`, ready to POST.
///
/// A domain wrapper over the serialized request (`Content-Type:
/// application/ocsp-request`) so [`build_request`] returns "an OCSP
/// request", not an anonymous `Vec<u8>` a caller could pass anywhere.
#[derive(Clone, Debug)]
pub struct OcspRequest(Vec<u8>);

impl OcspRequest {
    /// The request's DER bytes, for the HTTP POST body.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// Build the DER bytes of an `OCSPRequest` for one cert lookup,
/// using SHA-1 as the `CertID.hashAlgorithm`.
///
/// `issuer_name_sha1` is the SHA-1 hash of the **issuer's
/// DER-encoded `Name`** (the value bytes that an X.509 Name
/// SEQUENCE wraps -- equivalent to OpenSSL
/// `X509_NAME_hash_old`). `issuer_key_sha1` is the SHA-1 hash
/// of the issuer's **`subjectPublicKeyInfo.subjectPublicKey`
/// BIT STRING value** (the key bits with the leading "unused
/// bits" byte stripped, per RFC 6960 sec.4.1.1). `serial` is
/// the target cert's serial INTEGER value bytes.
///
/// Layered above this module: a thin helper that takes a
/// parsed issuer [`crate::x509::Certificate`] and a target
/// [`crate::x509::Certificate`], computes both SHA-1 hashes,
/// and calls in here. That helper lives outside lib-core to
/// keep this crate dep-light.
///
/// # Errors
/// [`spki::der::Error`] if a `CertID` field or the request body
/// fails DER construction. Unreachable for a parser-validated
/// [`CertSerial`] and a fixed-size SHA-1 hash -- surfaced rather
/// than panicked, since DER encoding is fallible in principle.
#[inline]
pub fn build_request(
    issuer_name_sha1: IssuerNameHash,
    issuer_key_sha1: IssuerKeyHash,
    serial: &CertSerial,
) -> Result<OcspRequest, spki::der::Error> {
    OcspHelpers::encode_request(&issuer_name_sha1, &issuer_key_sha1, serial, None).map(OcspRequest)
}

/// `build_request` plus an OCSP nonce extension (RFC 8954).
///
/// The nonce should be 16-32 bytes of fresh randomness drawn via
/// [`OcspNonce::random`] (the `crate::rng` fail-closed seam); the
/// responder echoes it back, defeating replay of an old signed
/// response.
///
/// # Errors
/// As for [`build_request`].
#[inline]
pub fn build_request_with_nonce(
    issuer_name_sha1: IssuerNameHash,
    issuer_key_sha1: IssuerKeyHash,
    serial: &CertSerial,
    nonce: &OcspNonce,
) -> Result<OcspRequest, spki::der::Error> {
    OcspHelpers::encode_request(&issuer_name_sha1, &issuer_key_sha1, serial, Some(nonce))
        .map(OcspRequest)
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct OcspHelpers;

impl OcspHelpers {
    /// Encode an `OCSPRequest` for one cert lookup via x509-ocsp,
    /// SHA-1 as the `CertID.hashAlgorithm`, the optional signature
    /// omitted (RFC 6960 §4.1.1 -- responders accept unsigned
    /// requests). With `nonce`, appends the `id-pkix-ocsp-nonce`
    /// extension (RFC 8954 §2.1); the nonce bytes are the caller's,
    /// drawn through the `crate::rng` seam, not a second RNG path.
    fn encode_request(
        issuer_name_sha1: &IssuerNameHash,
        issuer_key_sha1: &IssuerKeyHash,
        serial: &CertSerial,
        nonce: Option<&OcspNonce>,
    ) -> Result<Vec<u8>, spki::der::Error> {
        use spki::AlgorithmIdentifierOwned;
        use spki::der::Encode as _;
        use spki::der::asn1::{Null, OctetString};
        use x509_cert::ext::AsExtension as _;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_ocsp::{CertId, OcspRequest as X509OcspRequest, Request, TbsRequest, ext::Nonce};

        let cert_id = CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: OID_SHA1,
                parameters: Some(Null.into()),
            },
            issuer_name_hash: OctetString::new(issuer_name_sha1.0.to_vec())?,
            issuer_key_hash: OctetString::new(issuer_key_sha1.0.to_vec())?,
            serial_number: SerialNumber::new(serial.as_bytes())?,
        };
        // `request_extensions` is x509-cert's `Option<Extensions>`
        // (`Extensions = SEQUENCE OF Extension`); build it as a value,
        // not by poking a mutable field.
        let request_extensions = match nonce {
            None => None,
            // x509-ocsp owns the RFC 8954 nonce-extension encoding; the
            // entropy is the caller's seam-drawn bytes, not a new draw.
            // `to_extension`'s subject-DN / sibling-extension args exist
            // for extensions that derive from them -- the nonce derives
            // from neither, hence the empty defaults.
            Some(nonce) => Some(vec![
                Nonce::new(nonce.as_bytes())?.to_extension(&Name::default(), &[])?,
            ]),
        };
        let tbs = TbsRequest {
            request_list: vec![Request {
                req_cert: cert_id,
                single_request_extensions: None,
            }],
            request_extensions,
            ..TbsRequest::default()
        };
        X509OcspRequest {
            tbs_request: tbs,
            optional_signature: None,
        }
        .to_der()
    }
}

// ----- Response side -----

/// Top-level `OCSPResponseStatus` (RFC 6960 sec.4.2.1).
///
/// The ENUMERATED values 0..6 are defined; 4 is reserved.
/// Anything else surfaces as [`OcspResponseStatus::Other`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// Wire value 0: response generation succeeded (the only
    /// status that carries a `BasicOcspResponse` payload).
    Successful,
    /// Wire value 1: request couldn't be parsed.
    MalformedRequest,
    /// Wire value 2: internal responder error.
    InternalError,
    /// Wire value 3: try again later.
    TryLater,
    /// Wire value 5: request must be signed.
    SigRequired,
    /// Wire value 6: request unauthorized.
    Unauthorized,
    /// Any other ENUMERATED byte the responder returned (4 is
    /// reserved per RFC 6960; unknown values too). Tier 0 `u8`
    /// -- the spec ENUMERATED is open to extension.
    Other(u8),
}

impl OcspResponseStatus {
    /// Decode the raw ENUMERATED byte into the typed enum.
    /// Trust boundary for the OCSP `responseStatus` field.
    #[inline]
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Successful,
            1 => Self::MalformedRequest,
            2 => Self::InternalError,
            3 => Self::TryLater,
            5 => Self::SigRequired,
            6 => Self::Unauthorized,
            other => Self::Other(other),
        }
    }
}

/// Parsed `OCSPResponse`.
///
/// The optional `basic` field carries the [`BasicOcspResponse`]
/// when `responseStatus = successful` and the embedded
/// `responseBytes` use `id-pkix-ocsp-basic` (the only response
/// type RFC 6960 defines).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OcspResponse<'a> {
    /// Top-level `responseStatus` decoded from the ENUMERATED.
    pub status: OcspResponseStatus,
    /// Embedded `BasicOcspResponse` when `status == Successful`
    /// and the wrapped `responseBytes` use the
    /// `id-pkix-ocsp-basic` type; `None` otherwise.
    pub basic: Option<BasicOcspResponse<'a>>,
}

/// Parsed `BasicOCSPResponse.tbsResponseData` plus the outer
/// signature material.
#[non_exhaustive]
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "the parsed-once typed values (produced_at, tbs_response_data_der, signature_alg_oid, ...) are intentionally pub for read; responses is intentionally private behind the single_responses() accessor so callers read the typed per-entry SingleResponse values, not the raw Vec."
)]
pub struct BasicOcspResponse<'a> {
    /// `producedAt` from `tbsResponseData` per RFC 6960 §4.2.1
    /// -- the time the responder signed this reply.
    pub produced_at: DateTime,
    /// The decoded `tbsResponseData.responses`. Read via
    /// [`BasicOcspResponse::single_responses`].
    responses: Vec<SingleResponse>,
    /// `tbsResponseData` bytes (tag+length+value) -- exactly the
    /// bytes covered by the response signature.
    pub tbs_response_data_der: &'a [u8],
    /// `signatureAlgorithm.algorithm` OID body (the value of the
    /// `06 LL` TLV).
    pub signature_alg_oid: &'a [u8],
    /// Outer `signature` BIT STRING value with the unused-bits
    /// leading byte stripped.
    pub signature_bits: &'a [u8],
    /// DER bytes of each optional cert in the `[0] EXPLICIT
    /// certs SEQUENCE OF Certificate` field. Empty when the
    /// responder didn't embed any chain certs (it expects the
    /// caller to know the responder by some out-of-band means).
    pub embedded_cert_ders: Vec<&'a [u8]>,
    /// The OCSP nonce (RFC 8954) echoed in `responseExtensions`,
    /// when present -- match it against the request nonce.
    pub nonce: Option<Vec<u8>>,
}

impl BasicOcspResponse<'_> {
    /// Verify the response signature against the issuer's SPKI.
    ///
    /// # Errors
    /// As for `x509::verify_tbs_signature`.
    #[inline]
    pub fn verify_signature<B: AsRef<[u8]>>(
        &self,
        signer_spki_der: B,
    ) -> Result<(), crate::x509::VerifyError> {
        let signer_spki_der = signer_spki_der.as_ref();
        crate::x509::verify_tbs_signature(crate::x509::TbsSignature {
            tbs_der: self.tbs_response_data_der,
            signature_alg_oid: self.signature_alg_oid,
            signature_bits: self.signature_bits,
            issuer_spki_der: signer_spki_der,
        })
    }

    /// The per-cert `SingleResponse` entries of `tbsResponseData`.
    #[inline]
    #[must_use]
    pub(crate) fn single_responses(&self) -> &[SingleResponse] {
        &self.responses
    }

    /// Test-only convenience: find the `SingleResponse` whose
    /// `CertID` matches `serial`. Production reads status only via
    /// [`VerifiedOcspResponse::single_responses`] (trust by
    /// construction), so this exists just to keep the parser KATs
    /// terse; `#[cfg(test)]`-gated to stay off the production
    /// surface.
    #[cfg(test)]
    #[inline]
    #[must_use]
    pub(crate) fn find_serial(&self, serial: &CertSerial) -> Option<&SingleResponse> {
        self.single_responses()
            .iter()
            .find(|r| &r.cert_id.serial == serial)
    }
}

/// A [`BasicOcspResponse`] whose responder signature has been
/// verified against a signer SPKI.
///
/// Trust by construction (see `doc/typing-discipline.md`): the only
/// production constructor is [`VerifiedOcspResponse::verify`], so
/// holding this type is proof the response signature checked against
/// a signer. Per-cert revocation status
/// ([`crate::revocation::check_against_ocsp_response`] via
/// `find_serial`) is reachable *only* through a
/// verified response -- you cannot read a status off an unverified
/// OCSP reply, by type.
#[derive(Debug, Clone)]
pub struct VerifiedOcspResponse<'a> {
    /// The verified inner response.
    basic: BasicOcspResponse<'a>,
}

impl<'a> VerifiedOcspResponse<'a> {
    /// Verify `basic`'s responder signature against `signer_spki`
    /// and, on success, wrap it as a [`VerifiedOcspResponse`]. The
    /// only production door to a verified response.
    ///
    /// # Errors
    /// [`crate::x509::VerifyError`] when the signature does not
    /// verify against `signer_spki`.
    #[inline]
    pub fn verify(
        basic: &BasicOcspResponse<'a>,
        signer_spki: &crate::x509::SpkiDer<'_>,
    ) -> Result<Self, crate::x509::VerifyError> {
        basic.verify_signature(signer_spki.as_der())?;
        Ok(Self {
            basic: basic.clone(),
        })
    }

    /// The per-cert `SingleResponse` entries of this *verified*
    /// response. Reachable only on a verified response, so any status
    /// read is proof of a checked signature.
    #[inline]
    #[must_use]
    pub(crate) fn single_responses(&self) -> &[SingleResponse] {
        self.basic.single_responses()
    }

    /// Test-only: wrap a basic response *without* verifying its
    /// signature, to exercise status-translation logic in isolation.
    /// `#[cfg(test)]`-gated, so the production "only door is
    /// `verify`" guarantee is unaffected.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_unverified_basic_for_test(basic: BasicOcspResponse<'a>) -> Self {
        Self { basic }
    }
}

/// One entry in a `BasicOCSPResponse.responses`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SingleResponse {
    /// `CertID` identifying which certificate this entry is about.
    pub cert_id: CertId,
    /// `certStatus` CHOICE -- Good / Revoked{at, reason} /
    /// Unknown per RFC 6960 §4.2.1.
    pub status: CertStatus,
    /// `thisUpdate` -- timestamp at which the responder asserts
    /// this status was current.
    pub this_update: DateTime,
    /// `nextUpdate` when the responder commits to a refresh
    /// horizon; `None` for responders that don't.
    pub next_update: Option<DateTime>,
}

/// `CertID` -- which certificate a [`SingleResponse`] is about.
///
/// Only the serial is surfaced: matching is by serial against the
/// cert the request asked about. The issuer name/key hashes echo
/// the request's `CertID` and are not consumed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertId {
    /// `serialNumber` of the certificate this entry is about.
    pub serial: CertSerial,
}

/// `CertStatus` CHOICE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Cert is not revoked (`good` per RFC 6960 §4.2.1).
    Good,
    /// Cert is revoked; carries the revocation timestamp and
    /// optional reason code.
    Revoked {
        /// `revocationTime` per RFC 6960 §4.2.2.2.
        revoked_at: DateTime,
        /// `CRLReason` (RFC 5280 sec.5.3.1) when the responder
        /// includes it. `None` means no reason was supplied.
        reason: Option<crate::crl::CrlReason>,
    },
    /// Responder has no information about this cert (out of its
    /// authority, or unknown serial).
    Unknown,
}

/// Owning wrapper around a parsed OCSP response.
///
/// Same pattern as [`crate::x509::OwnedCert`] /
/// [`crate::crl::OwnedCrl`]: holds the OCSP response DER plus a
/// re-parseable view. Public entry point under typing-discipline
/// rule D; free `parse_response` is `pub(crate)` because it
/// returns a borrowed view tied to the input.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OwnedOcspResponse {
    /// DER bytes of the outer `OCSPResponse` SEQUENCE (RFC 6960
    /// §4.2.1). Validated at construction via [`parse_response`];
    /// the [`Self::view`] re-parse cannot fail because the
    /// buffer is owned and immutable.
    der: Vec<u8>,
}

impl OwnedOcspResponse {
    /// Parse `der` as an OCSP response, allocating an owned copy
    /// so the wrapper is independent of the input borrow.
    ///
    /// # Errors
    /// [`X509Error`] from the OCSP parser.
    #[inline]
    pub fn from_der<B: AsRef<[u8]>>(der: B) -> Result<Self, X509Error> {
        let bytes = der.as_ref().to_vec();
        // Validate the DER at construction; the parsed view borrows
        // `bytes` and is dropped immediately. `drop()` makes the
        // discard explicit (the parsed value owns a `Vec` of
        // borrowed cert DER slices, so the `let _` shape elides a
        // destructor).
        drop(OcspResponse::parse(&bytes)?);
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and hand back the borrowed view.
    ///
    /// # Performance
    /// Parses the DER on **every call** (O(n) in the DER length). For
    /// repeated field access bind the view once (`let resp = owned.view();`)
    /// and reuse it, rather than calling `view()` per field.
    ///
    /// # Panics
    /// Never -- [`from_der`] validated at construction.
    ///
    /// [`from_der`]: Self::from_der
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "Invariant: `from_der` parsed the same bytes and returned `Ok` before constructing `Self`; the bytes are owned and immutable, so re-parse cannot fail."
    )]
    #[inline]
    pub fn view(&self) -> OcspResponse<'_> {
        OcspResponse::parse(&self.der)
            .expect("OwnedOcspResponse: from_der validated DER at construction")
    }

    /// Raw DER bytes.
    #[inline]
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl<'a> OcspResponse<'a> {
    /// Parse an `OCSPResponse` DER blob.
    ///
    /// # Errors
    /// Any der decode failure, or a top-level shape that doesn't match
    /// `OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED,
    /// responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }`.
    #[inline]
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        let outer = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP not a TLV"))?;
        if outer.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure("OCSP not SEQUENCE"));
        }
        let mut reader = SliceReader::new(outer.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP body"))?;

        // responseStatus ENUMERATED.
        let status_any = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("missing responseStatus"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("missing responseStatus"))?;
        if status_any.tag() != Tag::Enumerated {
            return Err(X509Error::UnexpectedStructure("malformed responseStatus"));
        }
        let &[status_byte] = status_any.value() else {
            return Err(X509Error::UnexpectedStructure("malformed responseStatus"));
        };
        let status = OcspResponseStatus::from_byte(status_byte);

        // responseBytes [0] EXPLICIT { responseType OID, response OCTET STRING }.
        let mut basic: Option<BasicOcspResponse<'_>> = None;
        if status == OcspResponseStatus::Successful && !reader.is_finished() {
            let rb_explicit = AnyRef::from_der(
                reader
                    .tlv_bytes()
                    .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP responseBytes"))?,
            )
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP responseBytes"))?;
            if matches!(
                rb_explicit.tag(),
                Tag::ContextSpecific {
                    number: TagNumber::N0,
                    ..
                }
            ) {
                let rb_seq = AnyRef::from_der(rb_explicit.value()).map_err(|_ignored| {
                    X509Error::UnexpectedStructure("OCSP responseBytes not SEQUENCE")
                })?;
                let mut rb_reader = SliceReader::new(rb_seq.value()).map_err(|_ignored| {
                    X509Error::UnexpectedStructure("OCSP responseBytes body")
                })?;
                let rtype =
                    AnyRef::from_der(rb_reader.tlv_bytes().map_err(|_ignored| {
                        X509Error::UnexpectedStructure("missing responseType")
                    })?)
                    .map_err(|_ignored| X509Error::UnexpectedStructure("missing responseType"))?;
                // RFC 6960 defines only the basic-OCSP response type; any
                // other leaves `basic = None` and the caller falls back on
                // the top-level status.
                if rtype.tag() == Tag::ObjectIdentifier
                    && rtype.value() == known::BASIC_OCSP_RESPONSE.as_bytes()
                {
                    let resp_octet =
                        AnyRef::from_der(rb_reader.tlv_bytes().map_err(|_ignored| {
                            X509Error::UnexpectedStructure("missing response octet")
                        })?)
                        .map_err(|_ignored| {
                            X509Error::UnexpectedStructure("missing response octet")
                        })?;
                    if resp_octet.tag() != Tag::OctetString {
                        return Err(X509Error::UnexpectedStructure(
                            "response field not OCTET STRING",
                        ));
                    }
                    basic = Some(BasicOcspResponse::parse(resp_octet.value())?);
                }
            }
        }

        Ok(OcspResponse { status, basic })
    }
}

impl<'a> BasicOcspResponse<'a> {
    /// Decode the `BasicOCSPResponse` SEQUENCE (RFC 6960 §4.2.1).
    ///
    /// The outer fields are walked with der's `SliceReader` so the
    /// signature-covered `tbsResponseData` (and the embedded cert
    /// DERs) stay byte-exact zero-copy views; the structured
    /// `tbsResponseData` contents are decoded with x509-ocsp's typed
    /// `ResponseData`.
    fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        // BasicOCSPResponse ::= SEQUENCE {
        //   tbsResponseData ResponseData, signatureAlgorithm,
        //   signature BIT STRING, certs [0] EXPLICIT ... OPTIONAL }
        let outer = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("BasicOCSPResponse not a TLV"))?;
        if outer.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure(
                "BasicOCSPResponse not SEQUENCE",
            ));
        }
        let mut reader = SliceReader::new(outer.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("BasicOCSPResponse body"))?;

        // tbsResponseData -- exact bytes (the signature covers these).
        let tbs_response_data_der = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsResponseData"))?;

        // signatureAlgorithm AlgorithmIdentifier -- OID body.
        let sig_alg = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm"))?;
        let mut alg_reader = SliceReader::new(sig_alg.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm body"))?;
        let alg_oid =
            AnyRef::from_der(alg_reader.tlv_bytes().map_err(|_ignored| {
                X509Error::UnexpectedStructure("OCSP signatureAlgorithm OID")
            })?)
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signatureAlgorithm OID"))?;
        if alg_oid.tag() != Tag::ObjectIdentifier {
            return Err(X509Error::UnexpectedStructure(
                "OCSP signatureAlgorithm OID",
            ));
        }
        let signature_alg_oid = alg_oid.value();

        // signature BIT STRING -- strip the leading unused-bits byte.
        let sig_bits = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signature"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP signature"))?;
        if sig_bits.tag() != Tag::BitString {
            return Err(X509Error::UnexpectedStructure(
                "OCSP signature not BIT STRING",
            ));
        }
        let signature_bits = sig_bits
            .value()
            .get(1..)
            .ok_or(X509Error::UnexpectedStructure(
                "OCSP signature BIT STRING empty",
            ))?;

        // Optional [0] EXPLICIT certs SEQUENCE OF Certificate.
        let mut embedded_cert_ders: Vec<&[u8]> = Vec::new();
        if !reader.is_finished() {
            let certs_explicit = AnyRef::from_der(
                reader
                    .tlv_bytes()
                    .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certs field"))?,
            )
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certs field"))?;
            if matches!(
                certs_explicit.tag(),
                Tag::ContextSpecific {
                    number: TagNumber::N0,
                    ..
                }
            ) {
                let certs_seq = AnyRef::from_der(certs_explicit.value()).map_err(|_ignored| {
                    X509Error::UnexpectedStructure("OCSP certs not SEQUENCE")
                })?;
                let mut certs_reader = SliceReader::new(certs_seq.value())
                    .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP certs body"))?;
                while !certs_reader.is_finished() {
                    let cert_der = certs_reader
                        .tlv_bytes()
                        .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP embedded cert"))?;
                    embedded_cert_ders.push(cert_der);
                }
            }
        }

        // Structured tbsResponseData via x509-ocsp -- trust the type.
        let rd = x509_ocsp::ResponseData::from_der(tbs_response_data_der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("OCSP tbsResponseData decode"))?;
        let produced_at = Self::ocsp_date_time(&rd.produced_at);
        let nonce = rd.nonce().map(|n| n.0.as_bytes().to_vec());
        let responses = rd.responses.iter().map(Self::map_single_response).collect();

        Ok(BasicOcspResponse {
            produced_at,
            responses,
            tbs_response_data_der,
            signature_alg_oid,
            signature_bits,
            embedded_cert_ders,
            nonce,
        })
    }

    /// Bridge x509-ocsp's `OcspGeneralizedTime` to a [`DateTime`].
    fn ocsp_date_time(t: &x509_ocsp::OcspGeneralizedTime) -> DateTime {
        t.0.to_date_time()
    }

    /// Map an x509-ocsp `SingleResponse` to our owned view.
    fn map_single_response(sr: &x509_ocsp::SingleResponse) -> SingleResponse {
        SingleResponse {
            cert_id: CertId {
                serial: CertSerial::from_bytes(sr.cert_id.serial_number.as_bytes().to_vec()),
            },
            status: Self::map_cert_status(&sr.cert_status),
            this_update: Self::ocsp_date_time(&sr.this_update),
            next_update: sr.next_update.as_ref().map(Self::ocsp_date_time),
        }
    }

    /// Map an x509-ocsp `CertStatus` to ours, bridging x509-cert's
    /// `CrlReason` to our [`crate::crl::CrlReason`] by RFC 5280 code.
    fn map_cert_status(cs: &x509_ocsp::CertStatus) -> CertStatus {
        match cs {
            x509_ocsp::CertStatus::Good(_) => CertStatus::Good,
            x509_ocsp::CertStatus::Revoked(info) => CertStatus::Revoked {
                revoked_at: Self::ocsp_date_time(&info.revocation_time),
                reason: info.revocation_reason.map(Self::map_crl_reason),
            },
            x509_ocsp::CertStatus::Unknown(_) => CertStatus::Unknown,
        }
    }

    /// Bridge x509-cert's `CrlReason` to our [`crate::crl::CrlReason`]
    /// (same RFC 5280 sec.5.3.1 set; total, no numeric cast).
    const fn map_crl_reason(reason: X509CrlReason) -> crate::crl::CrlReason {
        use crate::crl::CrlReason as Ours;
        match reason {
            X509CrlReason::Unspecified => Ours::Unspecified,
            X509CrlReason::KeyCompromise => Ours::KeyCompromise,
            X509CrlReason::CaCompromise => Ours::CaCompromise,
            X509CrlReason::AffiliationChanged => Ours::AffiliationChanged,
            X509CrlReason::Superseded => Ours::Superseded,
            X509CrlReason::CessationOfOperation => Ours::CessationOfOperation,
            X509CrlReason::CertificateHold => Ours::CertificateHold,
            X509CrlReason::RemoveFromCRL => Ours::RemoveFromCrl,
            X509CrlReason::PrivilegeWithdrawn => Ours::PrivilegeWithdrawn,
            X509CrlReason::AaCompromise => Ours::AaCompromise,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{CertStatus, IssuerKeyHash, IssuerNameHash, OcspResponseStatus, build_request};
    use crate::identity::CertSerial;
    use core::str::FromStr as _;
    use spki::AlgorithmIdentifierOwned;
    use spki::der::asn1::{Any, BitString, Null, ObjectIdentifier, OctetString};
    use spki::der::{DateTime, Tag};
    use spki::der::{Decode as _, Encode as _};
    use x509_cert::ext::pkix::CrlReason as X509CrlReason;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_ocsp::{
        BasicOcspResponse, CertId, CertStatus as OcspCertStatus, OcspGeneralizedTime, OcspResponse,
        ResponderId, ResponseBytes, ResponseData, RevokedInfo, SingleResponse, Version,
    };

    /// Arbitrary distinct issuer hashes -- the values are irrelevant
    /// to these tests; only name-vs-key distinctness matters.
    const FILL_NAME_HASH: [u8; 20] = [0xAA; 20];
    const FILL_KEY_HASH: [u8; 20] = [0xBB; 20];
    /// Serial whose DER INTEGER the roundtrip test searches for.
    const ROUNDTRIP_SERIAL: [u8; 3] = [0x12, 0x34, 0x56];

    /// A distinct cert serial for fixtures. The value is arbitrary
    /// -- only uniqueness matters; OCSP matching keys on serial
    /// equality.
    fn fixture_serial(n: u8) -> CertSerial {
        CertSerial::from_bytes(vec![n])
    }

    /// A `GeneralizedTime` at the given civil-time components.
    fn ogtime(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> OcspGeneralizedTime {
        OcspGeneralizedTime::from(
            DateTime::new(year, month, day, hour, minute, second)
                .expect("fixture passes a valid civil date"),
        )
    }

    /// An `AlgorithmIdentifier` carrying just the given OID.
    fn alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    /// A `SingleResponse` about `serial` carrying `status`.
    fn single_response(serial: &CertSerial, status: OcspCertStatus) -> SingleResponse {
        SingleResponse {
            cert_id: CertId {
                hash_algorithm: alg(ObjectIdentifier::new_unwrap("1.3.14.3.2.26")), // id-sha1
                issuer_name_hash: OctetString::new(FILL_NAME_HASH.to_vec())
                    .expect("name hash fits an OCTET STRING"),
                issuer_key_hash: OctetString::new(FILL_KEY_HASH.to_vec())
                    .expect("key hash fits an OCTET STRING"),
                serial_number: SerialNumber::new(serial.as_bytes())
                    .expect("fixture serial encodes"),
            },
            cert_status: status,
            this_update: ogtime(2026, 5, 20, 12, 0, 0),
            next_update: None,
            single_extensions: None,
        }
    }

    /// Encode a *successful* `OCSPResponse` carrying one
    /// `SingleResponse`, via x509-ocsp's typed encoder.
    fn build_response(single: SingleResponse) -> Vec<u8> {
        let response_data = ResponseData {
            version: Version::default(),
            responder_id: ResponderId::ByName(
                Name::from_str("CN=Responder").expect("responder name parses"),
            ),
            produced_at: ogtime(2026, 5, 20, 12, 0, 0),
            responses: vec![single],
            response_extensions: None,
        };
        let basic = BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm: alg(ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11")), // sha256WithRSA
            signature: BitString::new(0, b"sig").expect("signature bits encode"),
            certs: None,
        };
        OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(ResponseBytes {
                response_type: ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1"),
                response: OctetString::new(basic.to_der().expect("basic response encodes to DER"))
                    .expect("basic response DER fits an OCTET STRING"),
            }),
        }
        .to_der()
        .expect("fixture OCSP response encodes to DER")
    }

    /// Encode a bare `OCSPResponse` SEQUENCE { responseStatus } with
    /// the raw status byte -- covers non-successful statuses and the
    /// out-of-range byte x509-ocsp's closed enum cannot represent.
    fn status_only_response(status_byte: u8) -> Vec<u8> {
        let enumerated = Any::new(Tag::Enumerated, vec![status_byte])
            .expect("status byte fits an ENUMERATED")
            .to_der()
            .expect("ENUMERATED encodes to DER");
        Any::new(Tag::Sequence, enumerated)
            .expect("status body fits a SEQUENCE")
            .to_der()
            .expect("status-only response encodes to DER")
    }

    #[test]
    fn build_request_decodes_as_one_request_ocsp_request() {
        let req = build_request(
            IssuerNameHash::new(FILL_NAME_HASH),
            IssuerKeyHash::new(FILL_KEY_HASH),
            &CertSerial::from_bytes(ROUNDTRIP_SERIAL.to_vec()),
        )
        .expect("request encodes");
        // Round-trips through x509-ocsp's own decoder -- a stronger
        // check than byte-grepping the hand-built TLV ever was.
        let decoded = x509_ocsp::OcspRequest::from_der(req.as_der()).expect("decodes");
        assert_eq!(decoded.tbs_request.request_list.len(), 1);
    }

    #[test]
    fn build_request_roundtrips_serial() {
        let req = build_request(
            IssuerNameHash::new(FILL_NAME_HASH),
            IssuerKeyHash::new(FILL_KEY_HASH),
            &CertSerial::from_bytes(ROUNDTRIP_SERIAL.to_vec()),
        )
        .expect("request encodes");
        let decoded = x509_ocsp::OcspRequest::from_der(req.as_der()).expect("decodes");
        let request = decoded
            .tbs_request
            .request_list
            .first()
            .expect("one request");
        assert_eq!(request.req_cert.serial_number.as_bytes(), ROUNDTRIP_SERIAL);
    }

    #[test]
    fn parse_response_decodes_good_status() {
        let serial = fixture_serial(1);
        let der = build_response(single_response(&serial, OcspCertStatus::Good(Null)));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        assert_eq!(resp.status, OcspResponseStatus::Successful);
        let basic = resp.basic.expect("basic present");
        assert_eq!(
            basic.produced_at,
            DateTime::new(2026, 5, 20, 12, 0, 0).expect("valid")
        );
        let single = basic.find_serial(&serial).expect("serial found");
        assert!(matches!(single.status, CertStatus::Good));
        let absent = fixture_serial(9);
        assert!(basic.find_serial(&absent).is_none());
    }

    #[test]
    fn parse_response_decodes_revoked_status_with_reason() {
        let revoked = OcspCertStatus::Revoked(RevokedInfo {
            revocation_time: ogtime(2026, 5, 1, 8, 0, 0),
            revocation_reason: Some(X509CrlReason::KeyCompromise),
        });
        let serial = fixture_serial(2);
        let der = build_response(single_response(&serial, revoked));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        let basic = resp.basic.expect("basic present");
        let sr = basic.find_serial(&serial).expect("serial found");
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "CertStatus is #[non_exhaustive]; the test asserts the Revoked-with-reason path and panics on every non-Revoked variant (Good, Unknown) or future addition with a Debug rendering for diagnosis."
        )]
        match sr.status {
            CertStatus::Revoked { revoked_at, reason } => {
                assert_eq!(revoked_at.year(), 2026);
                assert_eq!(reason, Some(crate::crl::CrlReason::KeyCompromise));
            }
            _ => panic!("expected Revoked, got {:?}", sr.status),
        }
    }

    #[test]
    fn parse_response_decodes_unknown_status() {
        let serial = fixture_serial(3);
        let der = build_response(single_response(&serial, OcspCertStatus::Unknown(Null)));
        let resp = super::OcspResponse::parse(&der).expect("parses");
        let basic = resp.basic.expect("basic present");
        let sr = basic.find_serial(&serial).expect("serial found");
        assert!(matches!(sr.status, CertStatus::Unknown));
    }

    #[test]
    fn parse_response_handles_try_later() {
        let der = status_only_response(3);
        let resp = super::OcspResponse::parse(&der).expect("parses");
        assert_eq!(resp.status, OcspResponseStatus::TryLater);
        assert!(resp.basic.is_none());
    }

    #[test]
    fn unknown_status_byte_falls_into_other() {
        let der = status_only_response(99);
        let resp = super::OcspResponse::parse(&der).expect("parses");
        assert_eq!(resp.status, OcspResponseStatus::Other(99));
    }
}
