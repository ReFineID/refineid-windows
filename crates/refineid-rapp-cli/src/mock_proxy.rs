//! Mock authorization proxy for RAPP automated verification and testing.
//!
//! Connects to a RAPP requester (such as `refineid-rapp pair-demo` or the
//! `ReFineID` Windows Settings app), performs `Noise_XXpsk3` pairing with a
//! 6-digit numeric pairing code or pairing offer URI, and serves typed card
//! operations (inspection, identity, certificate, and authentication).

#![expect(
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::assigning_clones,
    clippy::cloned_ref_to_slice_refs,
    clippy::collapsible_if,
    reason = "Mock proxy test harness with mock state serialization and session handling"
)]

use std::time::{Duration, Instant};

use refineid_rapp_core::cbor::Value;
use refineid_rapp_core::hashes::grants_hash;
use refineid_rapp_core::ids::{
    Challenge, PairId, PairingSecret, SessionId, derive_pair_id, derive_rendezvous_token,
    derive_session_id,
};
use refineid_rapp_core::limits::OFFER_TTL_MAX_MS;
use refineid_rapp_core::message::{
    Body, Envelope, NegotiatedParameters, ResultStatus, SessionParameters,
};
use refineid_rapp_core::noise::{
    CompletedHandshake, HandshakeRole, PairKeys, SecureChannel, generate_pair_keys,
    pairing_prologue, run_pairing_handshake, run_session_handshake, session_prologue,
};
use refineid_rapp_core::offer::{
    PairingOffer, TransportCandidate, offer_id_from_code, pairing_secret_from_code,
};
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING,
};
use refineid_rapp_core::stream::{
    StreamRendezvous, dial, stream_candidate_endpoints, stream_candidate_parameters,
};
use refineid_rapp_core::transport::{STREAM_PROFILE, TcpFrameTransport};
use refineid_rapp_core::{PAIRING_SUITE, SESSION_SUITE, WIRE_VERSION};

/// Default socket receive deadline.
const DEADLINE: Duration = Duration::from_secs(10);

/// Default candidate identifier.
const DEFAULT_CANDIDATE_ID: &str = "stream-1";

/// Default mock certificate DER payload.
pub const DEFAULT_MOCK_CERT_DER: &[u8] = include_bytes!("mock_cert.der");

/// Default mock P-384 private key scalar corresponding to `DEFAULT_MOCK_CERT_DER`.
pub const DEFAULT_MOCK_PRIVATE_KEY_SCALAR: &[u8; 48] = &[
    0x33, 0x51, 0xea, 0xcb, 0x1f, 0x41, 0x18, 0x9a, 0x6c, 0xdb, 0xbd, 0xae, 0x48, 0x27, 0xf1, 0xc1,
    0x47, 0x25, 0x4d, 0x3a, 0x56, 0x30, 0x53, 0xff, 0x6f, 0xd4, 0xd3, 0x76, 0xf8, 0x66, 0x8b, 0x2d,
    0x88, 0x78, 0xc4, 0xce, 0x86, 0x5a, 0xbb, 0xfd, 0xb3, 0x80, 0x1c, 0xae, 0x5b, 0x8e, 0x3d, 0xad,
];

/// Options configuring the mock proxy.
#[derive(Clone, Debug)]
pub struct MockProxyOptions {
    /// Explicit endpoint to connect to (e.g. "127.0.0.1:47110").
    pub connect: Option<String>,
    /// 6-digit numeric pairing code.
    pub code: Option<String>,
    /// Full RAPP pairing offer URI (`rapp:...`).
    pub uri: Option<String>,
    /// Candidate ID (default: "stream-1").
    pub candidate_id: String,
    /// Display name sent to requester.
    pub name: String,
    /// Platform string sent to requester.
    pub platform: String,
    /// Number of sessions to serve before exiting (default: 1; 0 means infinite).
    pub count: usize,
    /// Display name to return for identity operations.
    pub identity_name: String,
    /// Person identifier to return for identity operations.
    pub person_id: String,
    /// Certificate DER bytes to return.
    pub cert_der: Vec<u8>,
    /// Root CA certificate DER bytes to return (optional).
    pub root_ca_der: Option<Vec<u8>>,
    /// Intermediate CA certificate DER bytes to return (optional).
    pub intermediate_ca_der: Option<Vec<u8>>,
    /// PIN 1 remaining attempts.
    pub pin1_attempts: u8,
    /// PIN 2 remaining attempts.
    pub pin2_attempts: u8,
    /// Path to load existing proxy pairing state from.
    pub resume_state: Option<String>,
    /// Path to save proxy pairing state to.
    pub save_state: Option<String>,
}

impl Default for MockProxyOptions {
    fn default() -> Self {
        Self {
            connect: None,
            code: None,
            uri: None,
            candidate_id: DEFAULT_CANDIDATE_ID.to_owned(),
            name: "ReFineID Mock Phone".to_owned(),
            platform: "iOS".to_owned(),
            count: 1,
            identity_name: "TESTI TESTAAJA".to_owned(),
            person_id: "010101-999X".to_owned(),
            cert_der: DEFAULT_MOCK_CERT_DER.to_vec(),
            root_ca_der: None,
            intermediate_ca_der: None,
            pin1_attempts: 5,
            pin2_attempts: 5,
            resume_state: None,
            save_state: None,
        }
    }
}

/// A channel with proxy-side sequence tracking.
struct ProxyChannel {
    secure: SecureChannel<TcpFrameTransport>,
    session_id: SessionId,
    send_sequence: u64,
    receive_sequence: u64,
}

impl ProxyChannel {
    fn send(&mut self, body: Body) -> Result<(), String> {
        let envelope = Envelope {
            version: WIRE_VERSION,
            session_id: self.session_id,
            sequence: self.send_sequence,
            body,
        };
        self.send_sequence += 1;
        let encoded = envelope
            .encode()
            .map_err(|e| format!("envelope encode failed: {e:?}"))?;
        self.secure
            .send_plaintext(&encoded)
            .map_err(|e| format!("channel send failed: {e:?}"))?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Body, String> {
        let plaintext = self
            .secure
            .receive_plaintext()
            .map_err(|e| format!("channel receive failed: {e:?}"))?;
        let envelope =
            Envelope::decode(&plaintext).map_err(|e| format!("envelope decode failed: {e:?}"))?;
        if envelope.session_id != self.session_id {
            return Err(format!(
                "session id mismatch: expected {:?}, got {:?}",
                self.session_id, envelope.session_id
            ));
        }
        if envelope.sequence != self.receive_sequence {
            return Err(format!(
                "sequence gap: expected {}, got {}",
                self.receive_sequence, envelope.sequence
            ));
        }
        self.receive_sequence += 1;
        Ok(envelope.body)
    }
}

/// The proxy's stored pairing state.
#[derive(Debug)]
pub struct ProxyPairing {
    keys: PairKeys,
    requester_public: Vec<u8>,
    pair_id: PairId,
    grants: [u8; 32],
    rendezvous_token: refineid_rapp_core::ids::RendezvousToken,
    endpoint: String,
}

impl ProxyPairing {
    /// Saves the proxy pairing state to a simple hex-encoded text file.
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let content = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            hex::encode(self.pair_id.0),
            hex::encode(&self.keys.private),
            hex::encode(&self.keys.public),
            hex::encode(&self.requester_public),
            hex::encode(self.grants),
            hex::encode(self.rendezvous_token.0),
            self.endpoint
        );
        std::fs::write(path, content).map_err(|e| format!("cannot save state to {path}: {e}"))
    }

    /// Loads the proxy pairing state from a simple hex-encoded text file.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() < 7 {
            return Err("state file is truncated".into());
        }
        let pair_id_bytes = hex::decode(lines[0]).map_err(|e| format!("invalid pair_id: {e}"))?;
        let priv_bytes = hex::decode(lines[1]).map_err(|e| format!("invalid private key: {e}"))?;
        let pub_bytes = hex::decode(lines[2]).map_err(|e| format!("invalid public key: {e}"))?;
        let req_pub_bytes =
            hex::decode(lines[3]).map_err(|e| format!("invalid requester public: {e}"))?;
        let grants_bytes = hex::decode(lines[4]).map_err(|e| format!("invalid grants: {e}"))?;
        let token_bytes =
            hex::decode(lines[5]).map_err(|e| format!("invalid rendezvous token: {e}"))?;
        let endpoint = lines[6].trim().to_owned();

        if pair_id_bytes.len() != 16 || token_bytes.len() != 16 || grants_bytes.len() != 32 {
            return Err("state file has invalid field lengths".into());
        }

        let mut pair_id_arr = [0u8; 16];
        pair_id_arr.copy_from_slice(&pair_id_bytes);
        let mut token_arr = [0u8; 16];
        token_arr.copy_from_slice(&token_bytes);
        let mut grants_arr = [0u8; 32];
        grants_arr.copy_from_slice(&grants_bytes);

        Ok(Self {
            keys: PairKeys {
                private: zeroize::Zeroizing::new(priv_bytes),
                public: pub_bytes,
            },
            requester_public: req_pub_bytes,
            pair_id: PairId(pair_id_arr),
            grants: grants_arr,
            rendezvous_token: refineid_rapp_core::ids::RendezvousToken(token_arr),
            endpoint,
        })
    }
}

/// Runs the mock proxy workflow according to the provided options.
pub fn run_mock_proxy(options: MockProxyOptions) -> Result<(), String> {
    println!("starting RAPP mock proxy...");
    let pairing = if let Some(state_path) = &options.resume_state {
        println!("resuming from state file: {state_path}");
        let mut p = ProxyPairing::load_from_file(state_path)?;
        if let Some(connect) = &options.connect {
            p.endpoint = connect.clone();
        }
        p
    } else {
        let p = run_pairing(&options)?;
        if let Some(save_path) = &options.save_state {
            p.save_to_file(save_path)?;
            println!("saved proxy state to: {save_path}");
        }
        p
    };

    println!(
        "pairing active (pair_id: {}, rendezvous_token: {})",
        hex::encode(pairing.pair_id.0),
        hex::encode(pairing.rendezvous_token.0)
    );

    let mut sessions_served = 0;
    while options.count == 0 || sessions_served < options.count {
        sessions_served += 1;
        println!(
            "connecting session {sessions_served}{}...",
            if options.count > 0 {
                format!("/{}", options.count)
            } else {
                String::new()
            }
        );
        serve_one_session(&pairing, &options)?;
    }
    println!("mock proxy finished successfully (served {sessions_served} sessions)");
    Ok(())
}

fn run_pairing(options: &MockProxyOptions) -> Result<ProxyPairing, String> {
    let (offer, secret, endpoint) = resolve_offer_and_secret(options)?;
    println!("dialing pairing connection to {endpoint}...");
    let transport = dial(
        &[endpoint.clone()],
        &options.candidate_id,
        DEADLINE,
        &StreamRendezvous::Pairing,
    )
    .map_err(|e| format!("cannot connect to requester at {endpoint}: {e:?}"))?;

    let offer_hash = offer
        .offer_hash()
        .map_err(|e| format!("cannot hash offer: {e:?}"))?;
    let prologue = pairing_prologue(WIRE_VERSION, &offer_hash, STREAM_PROFILE)
        .map_err(|e| format!("cannot build pairing prologue: {e:?}"))?;
    let keys = generate_pair_keys().map_err(|e| format!("key generation failed: {e:?}"))?;

    println!("running Noise_XXpsk3 pairing handshake...");
    let done: CompletedHandshake<TcpFrameTransport> = run_pairing_handshake(
        HandshakeRole::Responder,
        transport,
        &keys,
        secret,
        &prologue,
    )
    .map_err(|e| format!("pairing handshake failed: {e:?}"))?;

    let requester_public = done
        .peer_static_public
        .ok_or("handshake did not yield requester public key")?;
    let session_id = derive_session_id(&done.handshake_hash);
    let pair_id = derive_pair_id(&done.handshake_hash);
    let rendezvous_token = derive_rendezvous_token(&done.handshake_hash);

    let mut channel = ProxyChannel {
        secure: done.channel,
        session_id,
        send_sequence: 0,
        receive_sequence: 0,
    };

    println!("exchanging pairing hello and confirm...");
    let hello = channel.receive()?;
    let Body::PairingHello {
        parameters: req_params,
        display_name: req_name,
        platform: req_plat,
        ..
    } = hello
    else {
        return Err(format!(
            "expected PairingHello from requester, got {hello:?}"
        ));
    };
    println!("requester hello from: {req_name} ({req_plat})");

    let resp_params = NegotiatedParameters {
        version: WIRE_VERSION,
        suite: PAIRING_SUITE.into(),
        offer_hash: req_params.offer_hash,
        transport_profile: STREAM_PROFILE.into(),
        candidate_id: options.candidate_id.clone(),
    };
    channel.send(Body::PairingHello {
        parameters: resp_params,
        display_name: options.name.clone(),
        platform: options.platform.clone(),
        requested_profiles: None,
    })?;

    let confirm = channel.receive()?;
    let Body::PairingConfirm { granted_profiles } = confirm else {
        return Err(format!(
            "expected PairingConfirm from requester, got {confirm:?}"
        ));
    };
    println!(
        "requester granted profiles: {}",
        granted_profiles.join(", ")
    );

    channel.send(Body::PairingConfirm {
        granted_profiles: granted_profiles.clone(),
    })?;
    let grants =
        grants_hash(&granted_profiles).map_err(|e| format!("cannot hash grants: {e:?}"))?;

    // Consume the pairing channel close.
    let close = channel.receive()?;
    let Body::SessionClose { .. } = close else {
        return Err(format!(
            "expected SessionClose on pairing channel, got {close:?}"
        ));
    };

    Ok(ProxyPairing {
        keys,
        requester_public,
        pair_id,
        grants,
        rendezvous_token,
        endpoint,
    })
}

fn resolve_offer_and_secret(
    options: &MockProxyOptions,
) -> Result<(PairingOffer, PairingSecret, String), String> {
    if let Some(uri) = &options.uri {
        let (offer, secret) =
            PairingOffer::from_uri(uri).map_err(|e| format!("invalid offer URI: {e:?}"))?;
        let endpoint = if let Some(explicit) = &options.connect {
            explicit.clone()
        } else {
            let candidate = offer
                .transports
                .iter()
                .find(|t| t.profile == STREAM_PROFILE)
                .ok_or("offer contains no stream candidate")?;
            let endpoints = stream_candidate_endpoints(&candidate.parameters)
                .map_err(|e| format!("invalid candidate endpoints: {e:?}"))?;
            endpoints
                .into_iter()
                .next()
                .ok_or("offer has empty endpoint list")?
        };
        Ok((offer, secret, endpoint))
    } else if let Some(code) = &options.code {
        let endpoint = options
            .connect
            .clone()
            .ok_or("--connect <host:port> is required when pairing with --code")?;
        let secret = pairing_secret_from_code(code);
        let offer_id = offer_id_from_code(code);
        let parameters = stream_candidate_parameters(&[endpoint.clone()])
            .map_err(|e| format!("candidate parameters failed: {e:?}"))?;
        let offer = PairingOffer {
            version: WIRE_VERSION,
            offer_id,
            suites: vec![PAIRING_SUITE.to_owned()],
            profiles: vec![
                PROFILE_CARD_STATUS.to_owned(),
                PROFILE_AUTHENTICATION.to_owned(),
                PROFILE_DOCUMENT_SIGNING.to_owned(),
            ],
            transports: vec![TransportCandidate {
                profile: STREAM_PROFILE.to_owned(),
                candidate_id: options.candidate_id.clone(),
                parameters,
            }],
            offer_ttl_ms: OFFER_TTL_MAX_MS,
        };
        Ok((offer, secret, endpoint))
    } else {
        Err("either --uri <rapp:...> or (--connect <host:port> and --code <code>) must be specified"
            .into())
    }
}

fn serve_one_session(pairing: &ProxyPairing, options: &MockProxyOptions) -> Result<(), String> {
    println!("dialing session connection to {}...", pairing.endpoint);
    let deadline = Instant::now() + Duration::from_secs(3600);
    let transport = loop {
        match dial(
            &[pairing.endpoint.clone()],
            &options.candidate_id,
            Duration::from_secs(2),
            &StreamRendezvous::Session(pairing.rendezvous_token),
        ) {
            Ok(t) => break t,
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("session connect timeout: {e:?}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    };

    let prologue = session_prologue(
        WIRE_VERSION,
        pairing.pair_id,
        &pairing.grants,
        STREAM_PROFILE,
    )
    .map_err(|e| format!("cannot build session prologue: {e:?}"))?;

    println!("running Noise_KK session handshake...");
    let done: CompletedHandshake<TcpFrameTransport> = run_session_handshake(
        HandshakeRole::Responder,
        transport,
        &pairing.keys.private,
        &pairing.requester_public,
        &prologue,
    )
    .map_err(|e| format!("session handshake failed: {e:?}"))?;

    let session_id = derive_session_id(&done.handshake_hash);
    let mut channel = ProxyChannel {
        secure: done.channel,
        session_id,
        send_sequence: 0,
        receive_sequence: 0,
    };

    println!("exchanging session ready...");
    let ready = channel.receive()?;
    let Body::SessionReady {
        parameters: seen, ..
    } = ready
    else {
        return Err(format!("expected SessionReady, got {ready:?}"));
    };

    let session_params = SessionParameters {
        version: WIRE_VERSION,
        suite: SESSION_SUITE.into(),
        transport_profile: STREAM_PROFILE.into(),
        candidate_id: options.candidate_id.clone(),
        grants_hash: pairing.grants,
    };
    if seen != session_params {
        return Err("requester session parameters did not match".into());
    }

    let nonce = Challenge::random()
        .map_err(|_| "random unavailable".to_owned())?
        .0;
    channel.send(Body::SessionReady {
        parameters: session_params,
        nonce,
    })?;
    println!("session ready; awaiting operation requests...");

    loop {
        let msg = match channel.receive() {
            Ok(m) => m,
            Err(e) => {
                println!("channel ended or closed: {e}");
                break;
            }
        };
        match msg {
            Body::OperationRequest {
                operation_id,
                request_hash,
                profile,
                action,
                payload,
                ..
            } => {
                println!("received operation request: action='{action}', profile='{profile}'");
                handle_operation_request(
                    &mut channel,
                    operation_id,
                    request_hash,
                    &action,
                    &payload,
                    options,
                )?;
            }
            Body::SessionClose { reason, .. } => {
                println!("requester closed session gracefully: {reason:?}");
                break;
            }
            other => {
                eprintln!("unexpected message in session: {other:?}");
                break;
            }
        }
    }
    Ok(())
}

fn handle_operation_request(
    channel: &mut ProxyChannel,
    operation_id: refineid_rapp_core::ids::OperationId,
    request_hash: [u8; 32],
    action: &str,
    payload: &[(String, Value)],
    options: &MockProxyOptions,
) -> Result<(), String> {
    match action {
        "inspect_card" => {
            println!("serving inspect_card operation");
            channel.send(Body::OperationResult {
                operation_id,
                request_hash,
                status: ResultStatus::Completed,
                error: None,
                body: vec![
                    ("type".to_owned(), Value::Text("inspection".into())),
                    ("pin1_factory".to_owned(), Value::Bool(false)),
                    ("pin2_factory".to_owned(), Value::Bool(false)),
                    (
                        "pin1_attempts".to_owned(),
                        Value::Unsigned(options.pin1_attempts.into()),
                    ),
                    (
                        "pin2_attempts".to_owned(),
                        Value::Unsigned(options.pin2_attempts.into()),
                    ),
                    ("puk_attempts".to_owned(), Value::Null),
                ],
            })?;
            let ack = channel.receive()?;
            let Body::OperationResultAck { .. } = ack else {
                return Err(format!("expected OperationResultAck, got {ack:?}"));
            };
            println!("inspect_card completed and acknowledged");
        }
        "read_identity" => {
            println!(
                "serving read_identity operation: '{}' ({})",
                options.identity_name, options.person_id
            );
            channel.send(Body::OperationResult {
                operation_id,
                request_hash,
                status: ResultStatus::Completed,
                error: None,
                body: vec![
                    ("type".to_owned(), Value::Text("identity".into())),
                    (
                        "display_name".to_owned(),
                        Value::Text(options.identity_name.clone()),
                    ),
                    (
                        "person_id".to_owned(),
                        Value::Text(options.person_id.clone()),
                    ),
                ],
            })?;
            let ack = channel.receive()?;
            let Body::OperationResultAck { .. } = ack else {
                return Err(format!("expected OperationResultAck, got {ack:?}"));
            };
            println!("read_identity completed and acknowledged");
        }
        "read_certificate" => {
            let kind = payload
                .iter()
                .find(|(k, _)| k == "kind")
                .and_then(|(_, v)| match v {
                    Value::Text(t) => Some(t.as_str()),
                    _ => None,
                })
                .unwrap_or("authentication");
            let der = match kind {
                "root_ca" => options
                    .root_ca_der
                    .as_deref()
                    .unwrap_or(DEFAULT_MOCK_CERT_DER),
                "intermediate_ca" => options
                    .intermediate_ca_der
                    .as_deref()
                    .unwrap_or(DEFAULT_MOCK_CERT_DER),
                _ => &options.cert_der,
            };
            println!(
                "serving read_certificate ({kind}) operation ({} bytes DER)",
                der.len()
            );
            channel.send(Body::OperationResult {
                operation_id,
                request_hash,
                status: ResultStatus::Completed,
                error: None,
                body: vec![
                    ("type".to_owned(), Value::Text("certificate".into())),
                    ("der".to_owned(), Value::Bytes(der.to_vec())),
                ],
            })?;
            let ack = channel.receive()?;
            let Body::OperationResultAck { .. } = ack else {
                return Err(format!("expected OperationResultAck, got {ack:?}"));
            };
            println!("read_certificate ({kind}) completed and acknowledged");
        }
        "browser_authenticate" | "sign_document" => {
            println!("serving consequential operation '{action}': sending OperationPrepared");
            channel.send(Body::OperationPrepared {
                operation_id,
                request_hash,
            })?;

            let commit = channel.receive()?;
            let Body::OperationCommit {
                operation_id: comm_id,
                request_hash: comm_hash,
            } = commit
            else {
                return Err(format!("expected OperationCommit, got {commit:?}"));
            };
            if comm_id != operation_id || comm_hash != request_hash {
                return Err("commit mismatch with prepared operation".into());
            }
            let sig_len = determine_signature_length(payload);
            let digest_bytes =
                payload
                    .iter()
                    .find(|(k, _)| k == "digest")
                    .and_then(|(_, v)| match v {
                        Value::Bytes(b) => Some(b.as_slice()),
                        _ => None,
                    });

            let sig_bytes = digest_bytes
                .and_then(|digest| {
                    use p384::ecdsa::signature::hazmat::PrehashSigner;
                    let signing_key =
                        p384::ecdsa::SigningKey::from_slice(DEFAULT_MOCK_PRIVATE_KEY_SCALAR)
                            .ok()?;
                    let signature: p384::ecdsa::Signature =
                        signing_key.sign_prehash(digest).ok()?;
                    Some(signature.to_bytes().to_vec())
                })
                .unwrap_or_else(|| vec![0xAB; sig_len]);

            channel.send(Body::OperationResult {
                operation_id,
                request_hash,
                status: ResultStatus::Completed,
                error: None,
                body: vec![
                    ("type".to_owned(), Value::Text("signature".into())),
                    ("bytes".to_owned(), Value::Bytes(sig_bytes)),
                ],
            })?;
            let ack = channel.receive()?;
            let Body::OperationResultAck { .. } = ack else {
                return Err(format!("expected OperationResultAck, got {ack:?}"));
            };
            println!("{action} completed and acknowledged (signature {sig_len} bytes)");
        }
        other => {
            println!("unsupported action '{other}', denying");
            channel.send(Body::OperationResult {
                operation_id,
                request_hash,
                status: ResultStatus::Denied,
                error: Some("unsupported operation".into()),
                body: Vec::new(),
            })?;
            let _ = channel.receive();
        }
    }
    Ok(())
}

fn determine_signature_length(payload: &[(String, Value)]) -> usize {
    for (key, val) in payload {
        if key == "algorithm" {
            if let Value::Text(algo) = val {
                return match algo.as_str() {
                    "ecdsa_sha256" => 64,
                    "ecdsa_sha512" => 132,
                    "rsa_pkcs1_sha256" | "rsa_pss_sha256" | "rsa_pkcs1_sha384" => 384,
                    _ => 96,
                };
            }
        }
    }
    96
}
