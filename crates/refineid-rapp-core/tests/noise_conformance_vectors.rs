//! Replay of the corpus `noise_handshake` fixed-transcript vectors.
//!
//! This crate's `noise` module drives handshakes with fresh ephemerals over
//! a transport, so a fixed transcript cannot pass through it. The replay
//! instead uses the `snow` builder directly with the corpus's test-only
//! keys, while the prologue bytes and every derived identifier are asserted
//! through this crate's public helpers.

use refineid_rapp_core::ids::{
    PAIR_ID_LENGTH, PairId, RENDEZVOUS_TOKEN_LENGTH, SESSION_ID_LENGTH, derive_pair_id,
    derive_rendezvous_token, derive_session_id,
};
use refineid_rapp_core::limits::NOISE_MAX_MESSAGE;
use refineid_rapp_core::noise::{pairing_prologue, session_prologue};
use refineid_rapp_core::{PAIRING_SUITE, SESSION_SUITE, WIRE_VERSION};
use serde::Deserialize;
use snow::params::{DHChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::{Builder, HandshakeState};

mod corpus_util;
use corpus_util::{CORPUS_JSON, decode_hex, fixed};

/// Vectors in the `noise_handshake` section.
const NOISE_HANDSHAKE_COUNT: usize = 2;

/// The pre-shared-key slot of the pairing construction (specification
/// Section 8.1: the bearer secret is mixed as `psk3`).
const PAIRING_PSK_SLOT: u8 = 3;

/// Bytes in an X25519 private or public key.
const X25519_KEY_LENGTH: usize = 32;
/// Bytes in a SHA-256 digest.
const SHA256_LENGTH: usize = 32;

/// The corpus section this file replays.
#[derive(Deserialize)]
struct Corpus {
    noise_handshake: Vec<NoiseVector>,
}

/// One fixed-transcript handshake vector.
#[derive(Deserialize)]
struct NoiseVector {
    name: String,
    suite: String,
    transport_profile: String,
    test_only_initiator_static_private_hex: String,
    initiator_static_public_hex: String,
    test_only_responder_static_private_hex: String,
    responder_static_public_hex: String,
    test_only_initiator_ephemeral_private_hex: String,
    test_only_responder_ephemeral_private_hex: String,
    prologue_hex: String,
    messages_hex: Vec<String>,
    handshake_hash_hex: String,
    session_id_hex: String,
    #[serde(default)]
    pair_id_hex: Option<String>,
    #[serde(default)]
    rendezvous_token_hex: Option<String>,
    #[serde(default)]
    test_only_pairing_secret_hex: Option<String>,
    #[serde(default)]
    offer_hash_hex: Option<String>,
    #[serde(default)]
    grants_hash_hex: Option<String>,
}

#[test]
fn fixed_noise_transcripts_match_the_corpus() {
    let corpus: Corpus =
        serde_json::from_str(CORPUS_JSON).expect("the vendored RAPP corpus must be valid JSON");
    assert_eq!(corpus.noise_handshake.len(), NOISE_HANDSHAKE_COUNT);
    for vector in &corpus.noise_handshake {
        match vector.name.as_str() {
            "pairing-xxpsk3-fixed-transcript" => verify_pairing(vector),
            "session-kk-fixed-transcript" => verify_session(vector),
            name => panic!("unknown Noise vector {name}"),
        }
    }
}

/// Replays the pairing handshake transcript and its derived identifiers.
fn verify_pairing(vector: &NoiseVector) {
    assert_eq!(vector.suite, PAIRING_SUITE, "pairing suite name");
    let initiator_static =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_initiator_static_private_hex);
    let responder_static =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_responder_static_private_hex);
    let initiator_ephemeral =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_initiator_ephemeral_private_hex);
    let responder_ephemeral =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_responder_ephemeral_private_hex);
    let pairing_secret = fixed::<SHA256_LENGTH>(
        vector
            .test_only_pairing_secret_hex
            .as_deref()
            .expect("the pairing vector carries the bearer secret"),
    );
    let offer_hash = fixed::<SHA256_LENGTH>(
        vector
            .offer_hash_hex
            .as_deref()
            .expect("the pairing vector carries the offer hash"),
    );
    verify_static_public_keys(vector, &initiator_static, &responder_static);

    let prologue = pairing_prologue(WIRE_VERSION, &offer_hash, &vector.transport_profile)
        .expect("pairing prologue must encode");
    assert_eq!(
        prologue,
        decode_hex(&vector.prologue_hex),
        "pairing prologue bytes"
    );

    let parameters: NoiseParams = PAIRING_SUITE.parse().expect("pairing suite must parse");
    let mut initiator = Builder::new(parameters.clone())
        .local_private_key(&initiator_static)
        .expect("initiator static key")
        .fixed_ephemeral_key_for_testing_only(&initiator_ephemeral)
        .psk(PAIRING_PSK_SLOT, &pairing_secret)
        .expect("initiator pre-shared key")
        .prologue(&prologue)
        .expect("initiator prologue")
        .build_initiator()
        .expect("pairing initiator");
    let mut responder = Builder::new(parameters)
        .local_private_key(&responder_static)
        .expect("responder static key")
        .fixed_ephemeral_key_for_testing_only(&responder_ephemeral)
        .psk(PAIRING_PSK_SLOT, &pairing_secret)
        .expect("responder pre-shared key")
        .prologue(&prologue)
        .expect("responder prologue")
        .build_responder()
        .expect("pairing responder");

    let messages = vec![
        transfer(&mut initiator, &mut responder),
        transfer(&mut responder, &mut initiator),
        transfer(&mut initiator, &mut responder),
    ];
    verify_completion(vector, &initiator, &responder, &messages);

    let handshake_hash = initiator.get_handshake_hash();
    assert_eq!(
        derive_pair_id(handshake_hash).0,
        fixed::<PAIR_ID_LENGTH>(
            vector
                .pair_id_hex
                .as_deref()
                .expect("the pairing vector carries the pair identifier")
        ),
        "derived pair identifier"
    );
    assert_eq!(
        derive_rendezvous_token(handshake_hash).0,
        fixed::<RENDEZVOUS_TOKEN_LENGTH>(
            vector
                .rendezvous_token_hex
                .as_deref()
                .expect("the pairing vector carries the rendezvous token")
        ),
        "derived rendezvous token"
    );
}

/// Replays the session handshake transcript.
fn verify_session(vector: &NoiseVector) {
    assert_eq!(vector.suite, SESSION_SUITE, "session suite name");
    let initiator_static =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_initiator_static_private_hex);
    let responder_static =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_responder_static_private_hex);
    let initiator_ephemeral =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_initiator_ephemeral_private_hex);
    let responder_ephemeral =
        fixed::<X25519_KEY_LENGTH>(&vector.test_only_responder_ephemeral_private_hex);
    let pair_id = PairId(fixed::<PAIR_ID_LENGTH>(
        vector
            .pair_id_hex
            .as_deref()
            .expect("the session vector carries the pair identifier"),
    ));
    let grants_hash = fixed::<SHA256_LENGTH>(
        vector
            .grants_hash_hex
            .as_deref()
            .expect("the session vector carries the grants hash"),
    );
    let initiator_public = verify_static_public_keys(vector, &initiator_static, &responder_static);
    let responder_public = public_key(&responder_static);

    let prologue = session_prologue(
        WIRE_VERSION,
        pair_id,
        &grants_hash,
        &vector.transport_profile,
    )
    .expect("session prologue must encode");
    assert_eq!(
        prologue,
        decode_hex(&vector.prologue_hex),
        "session prologue bytes"
    );

    let parameters: NoiseParams = SESSION_SUITE.parse().expect("session suite must parse");
    let mut initiator = Builder::new(parameters.clone())
        .local_private_key(&initiator_static)
        .expect("initiator static key")
        .remote_public_key(&responder_public)
        .expect("initiator remote key")
        .fixed_ephemeral_key_for_testing_only(&initiator_ephemeral)
        .prologue(&prologue)
        .expect("initiator prologue")
        .build_initiator()
        .expect("session initiator");
    let mut responder = Builder::new(parameters)
        .local_private_key(&responder_static)
        .expect("responder static key")
        .remote_public_key(&initiator_public)
        .expect("responder remote key")
        .fixed_ephemeral_key_for_testing_only(&responder_ephemeral)
        .prologue(&prologue)
        .expect("responder prologue")
        .build_responder()
        .expect("session responder");

    let messages = vec![
        transfer(&mut initiator, &mut responder),
        transfer(&mut responder, &mut initiator),
    ];
    verify_completion(vector, &initiator, &responder, &messages);
}

/// Asserts the transcript, hash, derived session identifier, and mutually
/// seen static keys of a finished handshake.
fn verify_completion(
    vector: &NoiseVector,
    initiator: &HandshakeState,
    responder: &HandshakeState,
    messages: &[Vec<u8>],
) {
    assert!(initiator.is_handshake_finished());
    assert!(responder.is_handshake_finished());
    assert_eq!(
        initiator.get_handshake_hash(),
        responder.get_handshake_hash(),
        "peers must agree on the handshake hash"
    );
    assert_eq!(
        initiator.get_handshake_hash(),
        decode_hex(&vector.handshake_hash_hex).as_slice(),
        "handshake hash"
    );
    let expected: Vec<Vec<u8>> = vector
        .messages_hex
        .iter()
        .map(|hex| decode_hex(hex))
        .collect();
    assert_eq!(messages, expected.as_slice(), "handshake transcript");
    assert_eq!(
        derive_session_id(initiator.get_handshake_hash()).0,
        fixed::<SESSION_ID_LENGTH>(&vector.session_id_hex),
        "derived session identifier"
    );
    assert_eq!(
        initiator
            .get_remote_static()
            .expect("initiator must see the responder static key"),
        decode_hex(&vector.responder_static_public_hex).as_slice(),
        "responder static key as seen by the initiator"
    );
    assert_eq!(
        responder
            .get_remote_static()
            .expect("responder must see the initiator static key"),
        decode_hex(&vector.initiator_static_public_hex).as_slice(),
        "initiator static key as seen by the responder"
    );
}

/// Asserts both corpus public keys against their private keys, returning
/// the initiator's public key.
fn verify_static_public_keys(
    vector: &NoiseVector,
    initiator_private: &[u8; X25519_KEY_LENGTH],
    responder_private: &[u8; X25519_KEY_LENGTH],
) -> Vec<u8> {
    let initiator_public = public_key(initiator_private);
    assert_eq!(
        initiator_public,
        decode_hex(&vector.initiator_static_public_hex),
        "initiator static public key"
    );
    assert_eq!(
        public_key(responder_private),
        decode_hex(&vector.responder_static_public_hex),
        "responder static public key"
    );
    initiator_public
}

/// Computes the X25519 public key of a corpus private key.
fn public_key(private: &[u8; X25519_KEY_LENGTH]) -> Vec<u8> {
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .expect("X25519 resolver");
    dh.set(private);
    dh.pubkey().to_vec()
}

/// Moves one empty-payload handshake message between the two states.
fn transfer(writer: &mut HandshakeState, reader: &mut HandshakeState) -> Vec<u8> {
    let mut message = vec![0u8; NOISE_MAX_MESSAGE];
    let length = writer
        .write_message(&[], &mut message)
        .expect("write the empty handshake payload");
    message.truncate(length);
    let mut payload = vec![0u8; NOISE_MAX_MESSAGE];
    let payload_length = reader
        .read_message(&message, &mut payload)
        .expect("read the handshake message");
    assert_eq!(payload_length, 0, "RAPP forbids Noise handshake payloads");
    message
}
