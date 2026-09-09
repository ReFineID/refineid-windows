// Copyright 2026 ReFineID contributors
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

//! The Windows `msroots` file: a PKCS#7 (CMS) certs-only bundle of
//! the DVV root/intermediate CAs.
//!
//! After reading the card's key-exchange and signature certificates
//! (`kscNN` / `kxcNN`), the Base CSP reads the special `msroots`
//! file to obtain the issuing CA chain as a PKCS#7 `SignedData` with
//! no signer -- exactly the convention `OpenSC`'s minidriver follows.
//! Windows uses it to build and validate the certificate chain.
//!
//! CA certificates can be fetched directly from the card (or supplied via RAPP)
//! and dynamically cached, falling back to embedded anchors if unavailable.
#![expect(
    clippy::redundant_pub_crate,
    reason = "This private helper module still uses pub(crate) for consistency with the other minidriver support modules"
)]

use std::sync::OnceLock;

/// PKCS#7 (CMS `SignedData`, certs-only) DER bytes served for the
/// Base CSP's `msroots` read. Embedded compile-time fallback.
pub(crate) const DVV_MSROOTS_PKCS7_DER: &[u8] = include_bytes!("../trust-anchors/dvv-msroots.p7b");

/// Dynamic cache holding CA certificates fetched from the card or proxy.
static ROOT_CERTIFICATES_CACHE: OnceLock<Box<RootCertificates>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct RootCertificates {
    pub(crate) pkcs7_bundle: Vec<u8>,
}

impl RootCertificates {
    pub(crate) const fn new(bundle: Vec<u8>) -> Self {
        Self {
            pkcs7_bundle: bundle,
        }
    }
}

/// Dynamically caches root/intermediate CA certificates.
pub(crate) fn set_root_certificates(bundle: Vec<u8>) {
    let _ = ROOT_CERTIFICATES_CACHE.set(Box::new(RootCertificates::new(bundle)));
}

/// Returns the active msroots PKCS#7 DER bundle.
///
/// Prefers dynamically fetched CA certificates from the card/proxy; falls back
/// to the embedded bundle if the card has not disclosed CA certs.
pub(crate) fn active_msroots_pkcs7_der() -> &'static [u8] {
    if let Some(cached) = ROOT_CERTIFICATES_CACHE.get() {
        &cached.pkcs7_bundle
    } else {
        DVV_MSROOTS_PKCS7_DER
    }
}

/// Encodes a sequence of X.509 DER certificates into a PKCS#7 (CMS)
/// certs-only `SignedData` structure.
pub(crate) fn build_pkcs7_certs_bundle(certs: &[&[u8]]) -> Vec<u8> {
    if certs.is_empty() {
        return DVV_MSROOTS_PKCS7_DER.to_vec();
    }
    refineid_lib_core::trust_roots::build_pkcs7_certs_bundle(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_msroots_fallback() {
        let bundle = active_msroots_pkcs7_der();
        assert!(!bundle.is_empty());
        assert_eq!(bundle[0], 0x30);
    }

    #[test]
    fn test_build_pkcs7_certs_bundle_empty() {
        let bundle = build_pkcs7_certs_bundle(&[]);
        assert_eq!(bundle, DVV_MSROOTS_PKCS7_DER);
    }

    #[test]
    fn test_build_pkcs7_certs_bundle_with_cert() {
        let dummy_cert = [0x30, 0x03, 0x02, 0x01, 0x01];
        let bundle = build_pkcs7_certs_bundle(&[&dummy_cert]);
        assert_eq!(bundle[0], 0x30);
        assert!(bundle.windows(dummy_cert.len()).any(|w| w == dummy_cert));
    }
}
