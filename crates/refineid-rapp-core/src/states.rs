//! The machine-readable transition model of specification Section 14,
//! transcribed from `rapp-state-machine-v26.8.17.233.yaml`.
//!
//! The normative endpoint state is the product of three instance machines:
//! pairing, session, and operation. Every transition carries a role, and an
//! endpoint implements exactly the transitions whose role includes it. The
//! tables here are data, not behavior: the requester engine consults its
//! role projection before changing state, so an engine step that the model
//! does not permit fails loudly instead of inventing a transition. If these
//! tables and the vendored YAML ever disagree, the YAML wins and the
//! discrepancy is a specification-tracking defect.

/// Which endpoint may take a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Only the requester projection.
    Requester,
    /// Only the proxy projection.
    Proxy,
    /// Both projections.
    Both,
}

impl Role {
    /// Whether the projection for `requester` endpoints includes this role.
    #[must_use]
    pub const fn includes_requester(self) -> bool {
        matches!(self, Self::Requester | Self::Both)
    }

    /// Whether the projection for `proxy` endpoints includes this role.
    #[must_use]
    pub const fn includes_proxy(self) -> bool {
        matches!(self, Self::Proxy | Self::Both)
    }
}

/// The guards of the model, by their YAML names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    /// No guard.
    Always,
    /// `user_initiated`.
    UserInitiated,
    /// `local_user_action`.
    LocalUserAction,
    /// `offer_valid_and_supported`.
    OfferValidAndSupported,
    /// `offer_live`.
    OfferLive,
    /// `transcript_matches`.
    TranscriptMatches,
    /// `granted_sets_equal`.
    GrantedSetsEqual,
    /// `pairing_paired`.
    PairingPaired,
    /// `initiation_permitted`.
    InitiationPermitted,
    /// `ready_parameters_match`.
    ReadyParametersMatch,
    /// `deadline_not_expired`.
    DeadlineNotExpired,
    /// `another_session_live`.
    AnotherSessionLive,
    /// `admission_permitted`.
    AdmissionPermitted,
    /// `hash_echo_matches`.
    HashEchoMatches,
    /// `hash_matches`.
    HashMatches,
    /// `zero_transmissions`.
    ZeroTransmissions,
    /// `proven_no_transmission`.
    ProvenNoTransmission,
    /// `profile_has_no_consequential_command`.
    ProfileHasNoConsequentialCommand,
}

/// Pairing-instance states (Section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingState {
    /// No peer keys exist.
    Unpaired,
    /// One manual QR offer is live (requester only).
    OfferActive,
    /// The pairing Noise handshake is in progress.
    Handshaking,
    /// The authenticated exchange awaits both approvals.
    Confirming,
    /// A durable pairing exists with no healthy session.
    PairedDisconnected,
    /// A durable pairing exists with a healthy or checking session.
    PairedConnected,
    /// The pairing was terminated — locally, by authenticated peer notice,
    /// by an authenticated protocol violation, or by credential rejection.
    Revoked,
}

/// Pairing-machine events, by their YAML names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingEvent {
    /// `create_offer`.
    CreateOffer,
    /// `offer_scanned`.
    OfferScanned,
    /// `candidate_connected`.
    CandidateConnected,
    /// `offer_expired_or_cancelled`.
    OfferExpiredOrCancelled,
    /// `handshake_authenticated`.
    HandshakeAuthenticated,
    /// `handshake_failed`.
    HandshakeFailed,
    /// `both_users_confirmed`.
    BothUsersConfirmed,
    /// `denied_aborted_or_timed_out`.
    DeniedAbortedOrTimedOut,
    /// `session_healthy`.
    SessionHealthy,
    /// `session_closed`.
    SessionClosed,
    /// `forget_pairing`.
    ForgetPairing,
    /// `authenticated_protocol_violation`.
    AuthenticatedProtocolViolation,
    /// `local_revoke`.
    LocalRevoke,
    /// `peer_revocation_notice`.
    PeerRevocationNotice,
}

/// Session-instance states (Section 14.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// No channel.
    Absent,
    /// Transport establishment only (requester side).
    Connecting,
    /// Noise handshake and ready comparison only.
    Authenticating,
    /// Liveness and at most one operation.
    Healthy,
    /// Liveness recovery only; new operations blocked.
    Checking,
    /// Operation classification, close notice, key destruction.
    Closing,
    /// Terminal session record; no traffic.
    Closed,
}

/// Session-machine events, by their YAML names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// `connect`.
    Connect,
    /// `transport_accepted`.
    TransportAccepted,
    /// `transport_connected`.
    TransportConnected,
    /// `transport_failed`.
    TransportFailed,
    /// `user_disconnect`.
    UserDisconnect,
    /// `handshake_complete`.
    HandshakeComplete,
    /// `second_session_detected`.
    SecondSessionDetected,
    /// `ready_verified`.
    ReadyVerified,
    /// `candidate_failure`.
    CandidateFailure,
    /// `busy_received`.
    BusyReceived,
    /// `peer_close_received`.
    PeerCloseReceived,
    /// `authenticated_protocol_violation`.
    AuthenticatedProtocolViolation,
    /// `liveness_missed`.
    LivenessMissed,
    /// `liveness_restored`.
    LivenessRestored,
    /// `liveness_deadline_expired`.
    LivenessDeadlineExpired,
    /// `local_close_requested`.
    LocalCloseRequested,
    /// `credential_rejected`.
    CredentialRejected,
    /// `card_completion_ambiguous`.
    CardCompletionAmbiguous,
    /// `session_integrity_failed`.
    SessionIntegrityFailed,
    /// `close_requested_by_pairing`.
    CloseRequestedByPairing,
    /// `local_security_shutdown`.
    LocalSecurityShutdown,
    /// `close_complete_or_deadline`.
    CloseCompleteOrDeadline,
}

/// Operation-instance states (Section 14.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    /// Admission state of a new instance.
    Idle,
    /// Valid request sent or received.
    Requested,
    /// The proxy is inspecting, presenting, or collecting (proxy only).
    AwaitingConsent,
    /// User approved; credential command count is zero.
    Prepared,
    /// Durable point of no return written.
    Committed,
    /// At-most-one card command may be in flight (proxy only).
    Executing,
    /// A terminal card result exists, not acknowledged (proxy only).
    ResultPending,
    /// The result was acknowledged.
    Completed,
    /// The user denied before commit.
    Denied,
    /// Cancellation or expiry proven before transmission.
    Cancelled,
    /// Non-credential policy or card rejection.
    Rejected,
    /// Invalid CAN, PIN 1, or PIN 2; the session must close.
    CredentialRejected,
    /// Card completion cannot be proven; retry forbidden.
    Ambiguous,
    /// A result exists but delivery was not acknowledged.
    DeliveryUncertain,
}

impl OperationState {
    /// Whether the state is a permanent journal record.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Denied
                | Self::Cancelled
                | Self::Rejected
                | Self::CredentialRejected
                | Self::Ambiguous
                | Self::DeliveryUncertain
        )
    }
}

/// Operation-machine events, by their YAML names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationEvent {
    /// `operation_request_sent`.
    OperationRequestSent,
    /// `operation_request_received`.
    OperationRequestReceived,
    /// `request_valid`.
    RequestValid,
    /// `request_invalid_or_unsupported`.
    RequestInvalidOrUnsupported,
    /// `cancel_received`.
    CancelReceived,
    /// `request_expired`.
    RequestExpired,
    /// `user_denied`.
    UserDenied,
    /// `retry_policy_refused`.
    RetryPolicyRefused,
    /// `invalid_can_or_pin1_or_pin2`.
    InvalidCanOrPin1OrPin2,
    /// `safe_reads_complete`.
    SafeReadsComplete,
    /// `user_approved_and_proxy_ready`.
    UserApprovedAndProxyReady,
    /// `valid_commit`.
    ValidCommit,
    /// `begin_card_command`.
    BeginCardCommand,
    /// `crash_recovered_without_terminal_result`.
    CrashRecoveredWithoutTerminalResult,
    /// `card_success`.
    CardSuccess,
    /// `card_policy_rejection`.
    CardPolicyRejection,
    /// `card_removed_before_transmit`.
    CardRemovedBeforeTransmit,
    /// `card_removed_or_transport_uncertain`.
    CardRemovedOrTransportUncertain,
    /// `session_closed_post_commit`.
    SessionClosedPostCommit,
    /// `valid_result_ack`.
    ValidResultAck,
    /// `session_closed_before_ack`.
    SessionClosedBeforeAck,
    /// `prepared_received`.
    PreparedReceived,
    /// `cancel_sent_or_request_expired`.
    CancelSentOrRequestExpired,
    /// `commit_sent`.
    CommitSent,
    /// `result_completed_received`.
    ResultCompletedReceived,
    /// `result_denied_received`.
    ResultDeniedReceived,
    /// `result_cancelled_received`.
    ResultCancelledReceived,
    /// `result_rejected_received`.
    ResultRejectedReceived,
    /// `result_credential_rejected_received`.
    ResultCredentialRejectedReceived,
    /// `result_ambiguous_received`.
    ResultAmbiguousReceived,
    /// `session_closed_pre_commit`.
    SessionClosedPreCommit,
}

/// One modeled transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition<State: 'static, Event: 'static> {
    /// The state the transition leaves.
    pub from: State,
    /// The event that triggers it.
    pub event: Event,
    /// The role that may take it.
    pub role: Role,
    /// Its guard.
    pub guard: Guard,
    /// The state it enters.
    pub to: State,
}

/// Shorthand for transcribing one YAML transition row.
const fn row<State, Event>(
    from: State,
    event: Event,
    role: Role,
    guard: Guard,
    to: State,
) -> Transition<State, Event> {
    Transition {
        from,
        event,
        role,
        guard,
        to,
    }
}

/// The pairing transitions, in YAML order with list-valued `from` expanded.
pub const PAIRING_TRANSITIONS: &[Transition<PairingState, PairingEvent>] = &[
    row(
        PairingState::Unpaired,
        PairingEvent::CreateOffer,
        Role::Requester,
        Guard::UserInitiated,
        PairingState::OfferActive,
    ),
    row(
        PairingState::Unpaired,
        PairingEvent::OfferScanned,
        Role::Proxy,
        Guard::OfferValidAndSupported,
        PairingState::Handshaking,
    ),
    row(
        PairingState::OfferActive,
        PairingEvent::CandidateConnected,
        Role::Requester,
        Guard::OfferLive,
        PairingState::Handshaking,
    ),
    row(
        PairingState::OfferActive,
        PairingEvent::OfferExpiredOrCancelled,
        Role::Requester,
        Guard::Always,
        PairingState::Unpaired,
    ),
    row(
        PairingState::Handshaking,
        PairingEvent::HandshakeAuthenticated,
        Role::Both,
        Guard::TranscriptMatches,
        PairingState::Confirming,
    ),
    row(
        PairingState::Handshaking,
        PairingEvent::HandshakeFailed,
        Role::Requester,
        Guard::Always,
        PairingState::OfferActive,
    ),
    row(
        PairingState::Handshaking,
        PairingEvent::HandshakeFailed,
        Role::Proxy,
        Guard::Always,
        PairingState::Unpaired,
    ),
    row(
        PairingState::Handshaking,
        PairingEvent::OfferExpiredOrCancelled,
        Role::Requester,
        Guard::Always,
        PairingState::Unpaired,
    ),
    row(
        PairingState::Confirming,
        PairingEvent::BothUsersConfirmed,
        Role::Both,
        Guard::GrantedSetsEqual,
        PairingState::PairedDisconnected,
    ),
    row(
        PairingState::Confirming,
        PairingEvent::DeniedAbortedOrTimedOut,
        Role::Both,
        Guard::Always,
        PairingState::Unpaired,
    ),
    row(
        PairingState::PairedDisconnected,
        PairingEvent::SessionHealthy,
        Role::Both,
        Guard::Always,
        PairingState::PairedConnected,
    ),
    row(
        PairingState::PairedConnected,
        PairingEvent::SessionClosed,
        Role::Both,
        Guard::Always,
        PairingState::PairedDisconnected,
    ),
    row(
        PairingState::PairedDisconnected,
        PairingEvent::ForgetPairing,
        Role::Both,
        Guard::LocalUserAction,
        PairingState::Unpaired,
    ),
    row(
        PairingState::PairedConnected,
        PairingEvent::ForgetPairing,
        Role::Both,
        Guard::LocalUserAction,
        PairingState::Unpaired,
    ),
    row(
        PairingState::PairedConnected,
        PairingEvent::AuthenticatedProtocolViolation,
        Role::Both,
        Guard::Always,
        PairingState::Revoked,
    ),
    row(
        PairingState::PairedConnected,
        PairingEvent::LocalRevoke,
        Role::Both,
        Guard::LocalUserAction,
        PairingState::Revoked,
    ),
    row(
        PairingState::PairedDisconnected,
        PairingEvent::LocalRevoke,
        Role::Both,
        Guard::LocalUserAction,
        PairingState::Revoked,
    ),
    row(
        PairingState::PairedConnected,
        PairingEvent::PeerRevocationNotice,
        Role::Both,
        Guard::Always,
        PairingState::Revoked,
    ),
    row(
        PairingState::Revoked,
        PairingEvent::ForgetPairing,
        Role::Both,
        Guard::LocalUserAction,
        PairingState::Unpaired,
    ),
];

/// The session transitions, in YAML order with list-valued `from` expanded.
pub const SESSION_TRANSITIONS: &[Transition<SessionState, SessionEvent>] = &[
    row(
        SessionState::Absent,
        SessionEvent::Connect,
        Role::Requester,
        Guard::InitiationPermitted,
        SessionState::Connecting,
    ),
    row(
        SessionState::Absent,
        SessionEvent::TransportAccepted,
        Role::Proxy,
        Guard::PairingPaired,
        SessionState::Authenticating,
    ),
    row(
        SessionState::Connecting,
        SessionEvent::TransportConnected,
        Role::Requester,
        Guard::Always,
        SessionState::Authenticating,
    ),
    row(
        SessionState::Connecting,
        SessionEvent::TransportFailed,
        Role::Requester,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Connecting,
        SessionEvent::UserDisconnect,
        Role::Requester,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::HandshakeComplete,
        Role::Both,
        Guard::Always,
        SessionState::Authenticating,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::SecondSessionDetected,
        Role::Proxy,
        Guard::AnotherSessionLive,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::ReadyVerified,
        Role::Both,
        Guard::ReadyParametersMatch,
        SessionState::Healthy,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::CandidateFailure,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::BusyReceived,
        Role::Requester,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::PeerCloseReceived,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::TransportFailed,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::AuthenticatedProtocolViolation,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::LivenessMissed,
        Role::Both,
        Guard::Always,
        SessionState::Checking,
    ),
    row(
        SessionState::Checking,
        SessionEvent::LivenessRestored,
        Role::Both,
        Guard::DeadlineNotExpired,
        SessionState::Healthy,
    ),
    row(
        SessionState::Checking,
        SessionEvent::LivenessDeadlineExpired,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::UserDisconnect,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::UserDisconnect,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::LocalCloseRequested,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::LocalCloseRequested,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::PeerCloseReceived,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::PeerCloseReceived,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Closing,
        SessionEvent::PeerCloseReceived,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::CredentialRejected,
        Role::Proxy,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::CredentialRejected,
        Role::Proxy,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::CardCompletionAmbiguous,
        Role::Proxy,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::CardCompletionAmbiguous,
        Role::Proxy,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::TransportFailed,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::TransportFailed,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::SessionIntegrityFailed,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::SessionIntegrityFailed,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::AuthenticatedProtocolViolation,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::AuthenticatedProtocolViolation,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::CloseRequestedByPairing,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::CloseRequestedByPairing,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Connecting,
        SessionEvent::CloseRequestedByPairing,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::CloseRequestedByPairing,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Healthy,
        SessionEvent::LocalSecurityShutdown,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Checking,
        SessionEvent::LocalSecurityShutdown,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Connecting,
        SessionEvent::LocalSecurityShutdown,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Authenticating,
        SessionEvent::LocalSecurityShutdown,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
    row(
        SessionState::Closing,
        SessionEvent::TransportFailed,
        Role::Both,
        Guard::Always,
        SessionState::Closing,
    ),
    row(
        SessionState::Closing,
        SessionEvent::CloseCompleteOrDeadline,
        Role::Both,
        Guard::Always,
        SessionState::Closed,
    ),
];

/// The operation transitions, in YAML order with list-valued `from`
/// expanded.
pub const OPERATION_TRANSITIONS: &[Transition<OperationState, OperationEvent>] = &[
    row(
        OperationState::Idle,
        OperationEvent::OperationRequestSent,
        Role::Requester,
        Guard::AdmissionPermitted,
        OperationState::Requested,
    ),
    row(
        OperationState::Idle,
        OperationEvent::OperationRequestReceived,
        Role::Proxy,
        Guard::AdmissionPermitted,
        OperationState::Requested,
    ),
    row(
        OperationState::Requested,
        OperationEvent::RequestValid,
        Role::Proxy,
        Guard::Always,
        OperationState::AwaitingConsent,
    ),
    row(
        OperationState::Requested,
        OperationEvent::RequestInvalidOrUnsupported,
        Role::Proxy,
        Guard::Always,
        OperationState::Rejected,
    ),
    row(
        OperationState::Requested,
        OperationEvent::CancelReceived,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::CancelReceived,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Requested,
        OperationEvent::RequestExpired,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::RequestExpired,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::UserDenied,
        Role::Proxy,
        Guard::Always,
        OperationState::Denied,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::RetryPolicyRefused,
        Role::Proxy,
        Guard::Always,
        OperationState::Rejected,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::InvalidCanOrPin1OrPin2,
        Role::Proxy,
        Guard::Always,
        OperationState::CredentialRejected,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::SafeReadsComplete,
        Role::Proxy,
        Guard::ProfileHasNoConsequentialCommand,
        OperationState::ResultPending,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::UserApprovedAndProxyReady,
        Role::Proxy,
        Guard::ZeroTransmissions,
        OperationState::Prepared,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::CancelReceived,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::RequestExpired,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::ValidCommit,
        Role::Proxy,
        Guard::HashMatches,
        OperationState::Committed,
    ),
    row(
        OperationState::Committed,
        OperationEvent::BeginCardCommand,
        Role::Proxy,
        Guard::ZeroTransmissions,
        OperationState::Executing,
    ),
    row(
        OperationState::Committed,
        OperationEvent::CancelReceived,
        Role::Proxy,
        Guard::ProvenNoTransmission,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Committed,
        OperationEvent::CrashRecoveredWithoutTerminalResult,
        Role::Both,
        Guard::Always,
        OperationState::Ambiguous,
    ),
    row(
        OperationState::Executing,
        OperationEvent::CrashRecoveredWithoutTerminalResult,
        Role::Both,
        Guard::Always,
        OperationState::Ambiguous,
    ),
    row(
        OperationState::Executing,
        OperationEvent::CardSuccess,
        Role::Proxy,
        Guard::Always,
        OperationState::ResultPending,
    ),
    row(
        OperationState::Executing,
        OperationEvent::InvalidCanOrPin1OrPin2,
        Role::Proxy,
        Guard::Always,
        OperationState::CredentialRejected,
    ),
    row(
        OperationState::Executing,
        OperationEvent::CardPolicyRejection,
        Role::Proxy,
        Guard::Always,
        OperationState::Rejected,
    ),
    row(
        OperationState::Executing,
        OperationEvent::CardRemovedBeforeTransmit,
        Role::Proxy,
        Guard::ProvenNoTransmission,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Executing,
        OperationEvent::CardRemovedOrTransportUncertain,
        Role::Proxy,
        Guard::Always,
        OperationState::Ambiguous,
    ),
    row(
        OperationState::Executing,
        OperationEvent::CancelReceived,
        Role::Proxy,
        Guard::Always,
        OperationState::Executing,
    ),
    row(
        OperationState::Executing,
        OperationEvent::SessionClosedPostCommit,
        Role::Proxy,
        Guard::Always,
        OperationState::Executing,
    ),
    row(
        OperationState::ResultPending,
        OperationEvent::ValidResultAck,
        Role::Proxy,
        Guard::Always,
        OperationState::Completed,
    ),
    row(
        OperationState::ResultPending,
        OperationEvent::SessionClosedBeforeAck,
        Role::Proxy,
        Guard::Always,
        OperationState::DeliveryUncertain,
    ),
    row(
        OperationState::Committed,
        OperationEvent::SessionClosedPostCommit,
        Role::Proxy,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Requested,
        OperationEvent::PreparedReceived,
        Role::Requester,
        Guard::HashEchoMatches,
        OperationState::Prepared,
    ),
    row(
        OperationState::Requested,
        OperationEvent::CancelSentOrRequestExpired,
        Role::Requester,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::CancelSentOrRequestExpired,
        Role::Requester,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::CommitSent,
        Role::Requester,
        Guard::Always,
        OperationState::Committed,
    ),
    row(
        OperationState::Requested,
        OperationEvent::ResultCompletedReceived,
        Role::Requester,
        Guard::ProfileHasNoConsequentialCommand,
        OperationState::Completed,
    ),
    row(
        OperationState::Requested,
        OperationEvent::ResultDeniedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Denied,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::ResultDeniedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Denied,
    ),
    row(
        OperationState::Requested,
        OperationEvent::ResultCancelledReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::ResultCancelledReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Committed,
        OperationEvent::ResultCancelledReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Requested,
        OperationEvent::ResultRejectedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Rejected,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::ResultRejectedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Rejected,
    ),
    row(
        OperationState::Committed,
        OperationEvent::ResultRejectedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Rejected,
    ),
    row(
        OperationState::Requested,
        OperationEvent::ResultCredentialRejectedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::CredentialRejected,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::ResultCredentialRejectedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::CredentialRejected,
    ),
    row(
        OperationState::Committed,
        OperationEvent::ResultCredentialRejectedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::CredentialRejected,
    ),
    row(
        OperationState::Committed,
        OperationEvent::ResultCompletedReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Completed,
    ),
    row(
        OperationState::Committed,
        OperationEvent::ResultAmbiguousReceived,
        Role::Requester,
        Guard::Always,
        OperationState::Ambiguous,
    ),
    row(
        OperationState::Committed,
        OperationEvent::SessionClosedPostCommit,
        Role::Requester,
        Guard::Always,
        OperationState::Ambiguous,
    ),
    row(
        OperationState::Requested,
        OperationEvent::SessionClosedPreCommit,
        Role::Both,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::AwaitingConsent,
        OperationEvent::SessionClosedPreCommit,
        Role::Both,
        Guard::Always,
        OperationState::Cancelled,
    ),
    row(
        OperationState::Prepared,
        OperationEvent::SessionClosedPreCommit,
        Role::Both,
        Guard::Always,
        OperationState::Cancelled,
    ),
];

/// Finds the modeled transition for one state, event, and endpoint role.
///
/// Returns `None` when the model has no matching row, in which case the
/// input belongs to exactly one unexpected-input policy class of Section
/// 14.5 and must not change machine state.
#[must_use]
pub fn requester_transition<State: PartialEq + Copy, Event: PartialEq + Copy>(
    table: &'static [Transition<State, Event>],
    from: State,
    event: Event,
) -> Option<&'static Transition<State, Event>> {
    table
        .iter()
        .find(|row| row.from == from && row.event == event && row.role.includes_requester())
}

/// Finds the modeled proxy-projection transition, for the loopback proxy.
#[must_use]
pub fn proxy_transition<State: PartialEq + Copy, Event: PartialEq + Copy>(
    table: &'static [Transition<State, Event>],
    from: State,
    event: Event,
) -> Option<&'static Transition<State, Event>> {
    table
        .iter()
        .find(|row| row.from == from && row.event == event && row.role.includes_proxy())
}

#[cfg(test)]
mod tests {
    use super::{OPERATION_TRANSITIONS, OperationState, SESSION_TRANSITIONS, requester_transition};

    #[test]
    fn tables_have_no_ambiguous_rows() {
        // Within one role projection a (from, event) pair selects at most
        // one row, so the machines are deterministic.
        for (index, first) in SESSION_TRANSITIONS.iter().enumerate() {
            for second in &SESSION_TRANSITIONS[index + 1..] {
                if first.from == second.from && first.event == second.event {
                    assert!(
                        !(first.role.includes_requester() && second.role.includes_requester()),
                        "ambiguous requester session row"
                    );
                    assert!(
                        !(first.role.includes_proxy() && second.role.includes_proxy()),
                        "ambiguous proxy session row"
                    );
                }
            }
        }
        for (index, first) in OPERATION_TRANSITIONS.iter().enumerate() {
            for second in &OPERATION_TRANSITIONS[index + 1..] {
                if first.from == second.from && first.event == second.event {
                    assert!(
                        !(first.role.includes_requester() && second.role.includes_requester()),
                        "ambiguous requester operation row"
                    );
                    assert!(
                        !(first.role.includes_proxy() && second.role.includes_proxy()),
                        "ambiguous proxy operation row"
                    );
                }
            }
        }
    }

    #[test]
    fn terminal_operation_states_have_no_outgoing_rows() {
        for row in OPERATION_TRANSITIONS {
            assert!(
                !row.from.is_terminal(),
                "terminal state {:?} has an outgoing transition",
                row.from
            );
        }
    }

    #[test]
    fn projections_select_expected_rows() {
        use super::{OperationEvent, SessionEvent, SessionState};
        // The requester never sees proxy-only rows.
        assert!(
            requester_transition(
                OPERATION_TRANSITIONS,
                OperationState::AwaitingConsent,
                OperationEvent::UserDenied
            )
            .is_none()
        );
        // A committed close is ambiguity on the requester...
        let requester_row = requester_transition(
            OPERATION_TRANSITIONS,
            OperationState::Committed,
            OperationEvent::SessionClosedPostCommit,
        )
        .expect("modeled row");
        assert_eq!(requester_row.to, OperationState::Ambiguous);
        // ...and proven cancellation on the proxy.
        let proxy_row = super::proxy_transition(
            OPERATION_TRANSITIONS,
            OperationState::Committed,
            OperationEvent::SessionClosedPostCommit,
        )
        .expect("modeled row");
        assert_eq!(proxy_row.to, OperationState::Cancelled);
        // The healthy-close family lands in closing for both roles.
        let close_row = requester_transition(
            SESSION_TRANSITIONS,
            SessionState::Healthy,
            SessionEvent::PeerCloseReceived,
        )
        .expect("modeled row");
        assert_eq!(close_row.to, SessionState::Closing);
    }
}
