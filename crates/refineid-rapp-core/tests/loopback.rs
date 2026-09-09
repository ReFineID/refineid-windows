//! Loopback conformance tests: the requester engine against a scripted
//! authorization proxy running the proxy projection over the same wire.
//!
//! The proxy here is test scaffolding, not a product: the real proxies are
//! the holder's phones. It speaks the exact wire so the requester is
//! exercised end to end - pairing with grant agreement, sessions with the
//! parameter echo, the prepare/commit/result exchange, denial, credential
//! rejection revoking the pairing, immediate revocation on the first
//! authenticated violation, and ambiguity on a committed close.

#![allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "tests panic to fail; documenting each panic adds nothing"
)]

use std::thread::JoinHandle;
use std::time::Duration;

use refineid_rapp_core::cbor::Value;
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, Requester, RequesterConfig, SessionError,
};
use refineid_rapp_core::hashes::grants_hash;
use refineid_rapp_core::ids::{
    Challenge, OfferId, PairId, PairingSecret, SessionId, derive_pair_id, derive_session_id,
};
use refineid_rapp_core::message::{
    Body, CloseReason, Envelope, NegotiatedParameters, ResultStatus, SessionParameters,
};
use refineid_rapp_core::noise::{
    CompletedHandshake, HandshakeRole, PairKeys, SecureChannel, generate_pair_keys,
    pairing_prologue, run_pairing_handshake, run_session_handshake, session_prologue,
};
use refineid_rapp_core::offer::{PairingOffer, TransportCandidate};
use refineid_rapp_core::operations::{
    CardOperation, CardOperationResult, KeyProfile, SignatureAlgorithm,
};
use refineid_rapp_core::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS};
use refineid_rapp_core::store::{
    MemoryJournal, MemoryPairingStore, OperationJournal, PairingDisposition, PairingStore,
};
use refineid_rapp_core::transport::{MEMORY_PROFILE, MemoryTransport};
use refineid_rapp_core::{PAIRING_SUITE, SESSION_SUITE, WIRE_VERSION};

/// A generous deadline for scripted exchanges.
const DEADLINE: Duration = Duration::from_secs(2);
/// The candidate identifier used by every loopback test.
const CANDIDATE: &str = "loopback-1";

/// The requester engine type under test.
type TestRequester = Requester<MemoryPairingStore, MemoryJournal>;

fn test_requester() -> TestRequester {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Windows".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    )
}

fn test_offer() -> PairingOffer {
    PairingOffer {
        version: WIRE_VERSION,
        offer_id: OfferId([0x51; 32]),
        suites: vec![PAIRING_SUITE.into()],
        profiles: vec![PROFILE_CARD_STATUS.into(), PROFILE_AUTHENTICATION.into()],
        transports: vec![TransportCandidate {
            profile: MEMORY_PROFILE.into(),
            candidate_id: CANDIDATE.into(),
            parameters: vec![],
        }],
        offer_ttl_ms: 120_000,
    }
}

/// A registered consequential operation for the authentication tests.
fn authentication_operation() -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: "kortti.tunnistautuminen.suomi.fi".into(),
        key_profile: KeyProfile::Rsa3072,
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        digest: vec![0x2a; SignatureAlgorithm::RsaPkcs1Sha256.digest_length()],
    }
}

/// A schema-exact completed inspection body for the scripted proxy.
fn inspection_body() -> Vec<(String, Value)> {
    vec![
        ("type".to_owned(), Value::Text("inspection".into())),
        ("pin1_factory".to_owned(), Value::Bool(false)),
        ("pin2_factory".to_owned(), Value::Bool(false)),
        ("pin1_attempts".to_owned(), Value::Unsigned(5)),
        ("pin2_attempts".to_owned(), Value::Unsigned(5)),
        ("puk_attempts".to_owned(), Value::Null),
    ]
}

/// The proxy's durable half of a pairing, kept across sessions.
struct ProxyPairing {
    keys: PairKeys,
    requester_public: Vec<u8>,
    pair_id: PairId,
    grants: [u8; 32],
}

/// An envelope channel with proxy-owned sequence numbers, so tests can
/// both conform and deliberately misbehave.
struct ProxyChannel {
    secure: SecureChannel<MemoryTransport>,
    session_id: SessionId,
    send_sequence: u64,
    receive_sequence: u64,
}

impl ProxyChannel {
    fn send(&mut self, body: Body) {
        let envelope = Envelope {
            version: WIRE_VERSION,
            session_id: self.session_id,
            sequence: self.send_sequence,
            body,
        };
        self.send_sequence += 1;
        self.secure
            .send_plaintext(&envelope.encode().unwrap())
            .unwrap();
    }

    /// Sends a body under a deliberately skipped sequence number: an
    /// authenticated protocol violation on the receiver.
    fn send_with_sequence_gap(&mut self, body: Body) {
        let envelope = Envelope {
            version: WIRE_VERSION,
            session_id: self.session_id,
            sequence: self.send_sequence + 1,
            body,
        };
        self.secure
            .send_plaintext(&envelope.encode().unwrap())
            .unwrap();
    }

    fn receive(&mut self) -> Body {
        let plaintext = self.secure.receive_plaintext().unwrap();
        let envelope = Envelope::decode(&plaintext).unwrap();
        assert_eq!(envelope.session_id, self.session_id);
        assert_eq!(envelope.sequence, self.receive_sequence);
        self.receive_sequence += 1;
        envelope.body
    }
}

/// Runs the proxy half of the pairing exchange and returns its stored half.
fn proxy_pair(
    transport: MemoryTransport,
    offer: &PairingOffer,
    secret: PairingSecret,
    granted: &[String],
) -> ProxyPairing {
    let offer_hash = offer.offer_hash().unwrap();
    let prologue = pairing_prologue(WIRE_VERSION, &offer_hash, MEMORY_PROFILE).unwrap();
    let keys = generate_pair_keys().unwrap();
    let done = run_pairing_handshake(
        HandshakeRole::Responder,
        transport,
        &keys,
        secret,
        &prologue,
    )
    .unwrap();
    let requester_public = done.peer_static_public.clone().unwrap();
    let session_id = derive_session_id(&done.handshake_hash);
    let pair_id = derive_pair_id(&done.handshake_hash);
    let mut channel = ProxyChannel {
        secure: done.channel,
        session_id,
        send_sequence: 0,
        receive_sequence: 0,
    };
    let parameters = NegotiatedParameters {
        version: WIRE_VERSION,
        suite: PAIRING_SUITE.into(),
        offer_hash,
        transport_profile: MEMORY_PROFILE.into(),
        candidate_id: CANDIDATE.into(),
    };
    let Body::PairingHello { .. } = channel.receive() else {
        panic!("expected the requester hello first");
    };
    channel.send(Body::PairingHello {
        parameters,
        display_name: "Phone".into(),
        platform: "iOS".into(),
        requested_profiles: None,
    });
    let Body::PairingConfirm { granted_profiles } = channel.receive() else {
        panic!("expected the requester confirmation");
    };
    assert_eq!(granted_profiles, granted);
    channel.send(Body::PairingConfirm {
        granted_profiles: granted.to_vec(),
    });
    let grants = grants_hash(granted).unwrap();
    // The requester closes the pairing channel; consume the notice.
    let Body::SessionClose { .. } = channel.receive() else {
        panic!("expected the pairing channel to close");
    };
    ProxyPairing {
        keys,
        requester_public,
        pair_id,
        grants,
    }
}

/// Accepts one session as the proxy and completes the ready exchange.
fn proxy_accept_session(pairing: &ProxyPairing, transport: MemoryTransport) -> ProxyChannel {
    let prologue = session_prologue(
        WIRE_VERSION,
        pairing.pair_id,
        &pairing.grants,
        MEMORY_PROFILE,
    )
    .unwrap();
    let done: CompletedHandshake<MemoryTransport> = run_session_handshake(
        HandshakeRole::Responder,
        transport,
        &pairing.keys.private,
        &pairing.requester_public,
        &prologue,
    )
    .unwrap();
    let session_id = derive_session_id(&done.handshake_hash);
    let mut channel = ProxyChannel {
        secure: done.channel,
        session_id,
        send_sequence: 0,
        receive_sequence: 0,
    };
    let parameters = SessionParameters {
        version: WIRE_VERSION,
        suite: SESSION_SUITE.into(),
        transport_profile: MEMORY_PROFILE.into(),
        candidate_id: CANDIDATE.into(),
        grants_hash: pairing.grants,
    };
    let Body::SessionReady {
        parameters: seen, ..
    } = channel.receive()
    else {
        panic!("expected the requester session.ready");
    };
    assert_eq!(seen, parameters);
    channel.send(Body::SessionReady {
        parameters,
        nonce: Challenge::random().unwrap().0,
    });
    channel
}

/// Pairs a fresh requester with a proxy thread and returns both halves.
fn paired(requester: &mut TestRequester, granted: &[String]) -> (PairId, ProxyPairing) {
    let offer = test_offer();
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let secret_bytes = [0x77u8; 32];
    let granted_for_proxy = granted.to_vec();
    let offer_for_proxy = offer.clone();
    let proxy: JoinHandle<ProxyPairing> = std::thread::spawn(move || {
        proxy_pair(
            proxy_transport,
            &offer_for_proxy,
            PairingSecret(secret_bytes),
            &granted_for_proxy,
        )
    });
    let profile_request: Vec<String> = granted.to_vec();
    let pair_id = requester
        .pair(
            &offer,
            PairingSecret(secret_bytes),
            &profile_request,
            requester_transport,
            |peer, _requested| {
                assert_eq!(peer.display_name, "Phone");
                Some(granted.to_vec())
            },
        )
        .unwrap();
    let proxy_pairing = proxy.join().unwrap();
    assert_eq!(proxy_pairing.pair_id, pair_id);
    (pair_id, proxy_pairing)
}

#[test]
fn pairing_stores_matching_records_on_both_sides() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, _proxy) = paired(&mut requester, &granted);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.granted_profiles, granted);
    assert_eq!(record.disposition, PairingDisposition::Paired);
    assert_eq!(record.peer_display_name, "Phone");
    assert_ne!(record.rendezvous_token.0, [0u8; 16]);
    assert_ne!(record.rendezvous_token.0, record.pair_id.0);
}

#[test]
fn wrong_secret_fails_pairing_without_storing() {
    let mut requester = test_requester();
    let offer = test_offer();
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let offer = test_offer();
        let offer_hash = offer.offer_hash().unwrap();
        let prologue = pairing_prologue(WIRE_VERSION, &offer_hash, MEMORY_PROFILE).unwrap();
        let keys = generate_pair_keys().unwrap();
        let _ = run_pairing_handshake(
            HandshakeRole::Responder,
            proxy_transport,
            &keys,
            PairingSecret([0x01; 32]),
            &prologue,
        );
    });
    let outcome = requester.pair(
        &offer,
        PairingSecret([0x02; 32]),
        &[PROFILE_CARD_STATUS.to_owned()],
        requester_transport,
        |_, _| panic!("an unauthenticated attempt must never reach confirmation"),
    );
    proxy.join().unwrap();
    assert!(matches!(
        outcome,
        Err(PairingError::HandshakeFailed | PairingError::Transport(_))
    ));
}

#[test]
fn card_status_completes_without_commit() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut channel = proxy_accept_session(&proxy_pairing, proxy_transport);
        let Body::OperationRequest {
            operation_id,
            request_hash,
            profile,
            ..
        } = channel.receive()
        else {
            panic!("expected an operation request");
        };
        assert_eq!(profile, PROFILE_CARD_STATUS);
        channel.send(Body::OperationResult {
            operation_id,
            request_hash,
            status: ResultStatus::Completed,
            error: None,
            body: inspection_body(),
        });
        let Body::OperationResultAck { .. } = channel.receive() else {
            panic!("expected the completed result to be acknowledged");
        };
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    let OperationOutcome::Completed(result) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(
        result,
        CardOperationResult::Inspection {
            pin1_factory: false,
            pin2_factory: false,
            pin1_attempts: Some(5),
            pin2_attempts: Some(5),
            puk_attempts: None,
        }
    );
}

#[test]
fn authentication_walks_prepare_commit_result() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut channel = proxy_accept_session(&proxy_pairing, proxy_transport);
        let Body::OperationRequest {
            operation_id,
            request_hash,
            ..
        } = channel.receive()
        else {
            panic!("expected an operation request");
        };
        channel.send(Body::OperationPrepared {
            operation_id,
            request_hash,
        });
        let Body::OperationCommit {
            operation_id: echoed_operation,
            request_hash: echoed_hash,
        } = channel.receive()
        else {
            panic!("expected a commit after prepared");
        };
        assert_eq!(echoed_operation, operation_id);
        assert_eq!(echoed_hash, request_hash);
        channel.send(Body::OperationResult {
            operation_id,
            request_hash,
            status: ResultStatus::Completed,
            error: None,
            body: vec![
                ("type".to_owned(), Value::Text("signature".into())),
                ("bytes".to_owned(), Value::Bytes(vec![0xAB; 96])),
            ],
        });
        let Body::OperationResultAck { .. } = channel.receive() else {
            panic!("expected the completed result to be acknowledged");
        };
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 60_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Signature(vec![0xAB; 96]))
    );
}

#[test]
fn denial_leaves_the_session_healthy() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut channel = proxy_accept_session(&proxy_pairing, proxy_transport);
        for _ in 0..2 {
            let Body::OperationRequest {
                operation_id,
                request_hash,
                ..
            } = channel.receive()
            else {
                panic!("expected an operation request");
            };
            channel.send(Body::OperationResult {
                operation_id,
                request_hash,
                status: ResultStatus::Denied,
                error: None,
                body: vec![],
            });
        }
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    for _ in 0..2 {
        let outcome = requester
            .execute(&mut session, &authentication_operation(), 30_000)
            .unwrap();
        assert_eq!(outcome, OperationOutcome::Denied);
    }
    proxy.join().unwrap();
}

#[test]
fn credential_rejection_revokes_the_pairing() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut channel = proxy_accept_session(&proxy_pairing, proxy_transport);
        let Body::OperationRequest {
            operation_id,
            request_hash,
            ..
        } = channel.receive()
        else {
            panic!("expected an operation request");
        };
        channel.send(Body::OperationResult {
            operation_id,
            request_hash,
            status: ResultStatus::CredentialRejected,
            error: None,
            body: vec![],
        });
        channel.send(Body::SessionClose {
            reason: CloseReason::CredentialRejected,
            last_received_sequence: 1,
        });
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::CredentialRejected);
    // Section 13.4: the authenticated credential_rejected result durably
    // revokes the pairing before the terminal outcome is reported.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.local_private.is_empty());
    assert!(record.peer_public.is_empty());

    // Recovery requires a new manual pairing ceremony.
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    drop(proxy_transport);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired(PairingDisposition::Revoked))
    ));
}

#[test]
fn committed_close_classifies_as_ambiguous() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut channel = proxy_accept_session(&proxy_pairing, proxy_transport);
        let Body::OperationRequest {
            operation_id,
            request_hash,
            ..
        } = channel.receive()
        else {
            panic!("expected an operation request");
        };
        channel.send(Body::OperationPrepared {
            operation_id,
            request_hash,
        });
        let Body::OperationCommit { .. } = channel.receive() else {
            panic!("expected a commit");
        };
        // The transport dies with the operation committed.
        drop(channel);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Ambiguous);
    // The journal remembers the prohibition on automatic retry (INV-06).
    let open = requester.journal().open_entries();
    assert!(open.is_empty());
}

#[test]
fn first_sequence_violation_revokes_the_pairing() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut channel = proxy_accept_session(&proxy_pairing, proxy_transport);
        let Body::OperationRequest {
            operation_id,
            request_hash,
            ..
        } = channel.receive()
        else {
            panic!("expected an operation request");
        };
        // A skipped sequence inside the authenticated channel is an
        // authenticated protocol violation on the receiver.
        channel.send_with_sequence_gap(Body::OperationResult {
            operation_id,
            request_hash,
            status: ResultStatus::Completed,
            error: None,
            body: vec![],
        });
        // The requester answers with its best-effort close.
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    // Pre-commit closure classifies the operation as cancelled.
    assert_eq!(outcome, OperationOutcome::Cancelled);
    // Section 14.6: the first authenticated violation revokes immediately.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.local_private.is_empty());
    assert!(record.peer_public.is_empty());

    // Revoked keys are never restored (INV-07).
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired(PairingDisposition::Revoked))
    ));
}
