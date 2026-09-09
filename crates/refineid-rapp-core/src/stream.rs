//! The `fi.refineid.stream.v1` transport profile of specification
//! Section 16.1.
//!
//! The requester runs the listener; the proxy dials, for both pairing and
//! sessions. Every connection opens with one plaintext rendezvous preamble
//! frame that selects which handshake the accepting requester initiates.
//! The preamble is unauthenticated routing metadata, exactly like a relay
//! token: it enables nothing but the selection, and every anomaly closes
//! the connection without touching stored state (Section 14.5, class 1).

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::cbor::Value;
use crate::ids::RendezvousToken;
use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};

/// Domain string opening every stream rendezvous preamble.
const STREAM_RENDEZVOUS_DOMAIN: &str = "RAPP-stream-v1";

/// Preamble purpose naming a pairing attempt.
const PURPOSE_PAIRING: &str = "pairing";

/// Preamble purpose naming a session attempt for a stored pairing.
const PURPOSE_SESSION: &str = "session";

/// Upper bound on an encoded rendezvous preamble frame; the listener
/// rejects a longer preamble before parsing it.
pub const MAX_STREAM_RENDEZVOUS_FRAME: usize = 64;

/// Candidate parameter key carrying the listener endpoint list.
const PARAMETER_ENDPOINTS: &str = "endpoints";

/// Maximum listener endpoints one stream candidate may carry.
pub const MAX_STREAM_ENDPOINTS: usize = 8;

/// Maximum UTF-8 bytes of one `host:port` endpoint literal.
pub const MAX_STREAM_ENDPOINT_BYTES: usize = 255;

/// One plaintext rendezvous preamble, the first frame on a fresh stream
/// connection before any Noise message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamRendezvous {
    /// Connect to the listener's currently active pairing offer.
    Pairing,
    /// Connect for a fresh session with the stored pairing this token
    /// names.
    Session(RendezvousToken),
}

impl StreamRendezvous {
    /// Encodes the preamble frame payload.
    ///
    /// # Errors
    ///
    /// Fails only when the value cannot be encoded within the wire limits.
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let (purpose, token_bytes) = match self {
            Self::Pairing => (PURPOSE_PAIRING, Vec::new()),
            Self::Session(token) => (PURPOSE_SESSION, token.0.to_vec()),
        };
        Value::Array(vec![
            Value::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            Value::Text(purpose.to_owned()),
            Value::Bytes(token_bytes),
        ])
        .encode()
        .map_err(|_| StreamError::Malformed)
    }

    /// Decodes and validates one received preamble frame payload.
    ///
    /// # Errors
    ///
    /// Every failure is pre-authentication invalid input: the caller closes
    /// the connection and changes no stored state.
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STREAM_RENDEZVOUS_FRAME {
            return Err(StreamError::Oversized);
        }
        let Ok(Value::Array(elements)) = Value::decode(bytes) else {
            return Err(StreamError::Malformed);
        };
        let [
            Value::Text(domain),
            Value::Text(purpose),
            Value::Bytes(token_bytes),
        ] = elements.as_slice()
        else {
            return Err(StreamError::Malformed);
        };
        if domain != STREAM_RENDEZVOUS_DOMAIN {
            return Err(StreamError::Malformed);
        }
        match purpose.as_str() {
            PURPOSE_PAIRING => {
                if token_bytes.is_empty() {
                    Ok(Self::Pairing)
                } else {
                    Err(StreamError::Malformed)
                }
            }
            PURPOSE_SESSION => {
                let token: [u8; crate::ids::RENDEZVOUS_TOKEN_LENGTH] = token_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StreamError::Malformed)?;
                Ok(Self::Session(RendezvousToken(token)))
            }
            _ => Err(StreamError::UnknownPurpose),
        }
    }
}

/// Builds the stream candidate `parameters` entries for a pairing offer.
///
/// # Errors
///
/// Fails on an empty list, more than [`MAX_STREAM_ENDPOINTS`] entries, or
/// an endpoint literal that is empty or exceeds
/// [`MAX_STREAM_ENDPOINT_BYTES`].
pub fn stream_candidate_parameters(
    endpoints: &[String],
) -> Result<Vec<(String, Value)>, StreamError> {
    validate_endpoints(endpoints)?;
    Ok(vec![(
        PARAMETER_ENDPOINTS.to_owned(),
        Value::Array(
            endpoints
                .iter()
                .map(|endpoint| Value::Text(endpoint.clone()))
                .collect(),
        ),
    )])
}

/// Reads the listener endpoints back out of stored candidate parameters.
///
/// # Errors
///
/// Fails when the parameters are not exactly the registered stream shape.
pub fn stream_candidate_endpoints(
    parameters: &[(String, Value)],
) -> Result<Vec<String>, StreamError> {
    let [(key, Value::Array(elements))] = parameters else {
        return Err(StreamError::Malformed);
    };
    if key != PARAMETER_ENDPOINTS {
        return Err(StreamError::Malformed);
    }
    let endpoints = elements
        .iter()
        .map(|element| match element {
            Value::Text(endpoint) => Ok(endpoint.clone()),
            _ => Err(StreamError::Malformed),
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_endpoints(&endpoints)?;
    Ok(endpoints)
}

fn validate_endpoints(endpoints: &[String]) -> Result<(), StreamError> {
    if endpoints.is_empty() || endpoints.len() > MAX_STREAM_ENDPOINTS {
        return Err(StreamError::EndpointCount);
    }
    if endpoints
        .iter()
        .any(|endpoint| endpoint.is_empty() || endpoint.len() > MAX_STREAM_ENDPOINT_BYTES)
    {
        return Err(StreamError::EndpointLength);
    }
    Ok(())
}

/// One accepted, preamble-classified stream connection.
#[derive(Debug)]
pub enum StreamAccept {
    /// The dialing proxy asked for the active pairing offer.
    Pairing(TcpFrameTransport),
    /// The dialing proxy asked for a fresh session with a stored pairing.
    Session {
        /// The pair-specific token from the preamble. The caller looks it
        /// up among non-revoked pairings and closes on no match.
        rendezvous_token: RendezvousToken,
        /// The connection, positioned after the preamble.
        transport: TcpFrameTransport,
    },
}

/// The requester's stream listener.
#[derive(Debug)]
pub struct StreamListener {
    listener: TcpListener,
    candidate_id: String,
    receive_deadline: Duration,
}

impl StreamListener {
    /// Binds the listener.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub fn bind(
        address: &str,
        candidate_id: &str,
        receive_deadline: Duration,
    ) -> Result<Self, StreamError> {
        let listener = TcpListener::bind(address).map_err(|_| StreamError::Bind)?;
        Ok(Self {
            listener,
            candidate_id: candidate_id.to_owned(),
            receive_deadline,
        })
    }

    /// The bound local port, for assembling advertised endpoints.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot report its address.
    pub fn local_port(&self) -> Result<u16, StreamError> {
        self.listener
            .local_addr()
            .map(|address| address.port())
            .map_err(|_| StreamError::Bind)
    }

    /// Accepts one connection, reads exactly one bounded preamble frame,
    /// and classifies it. A connection whose preamble is invalid is closed
    /// and reported; stored state never changes here.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept(&self) -> Result<StreamAccept, StreamError> {
        let (socket, _peer) = self.listener.accept().map_err(|_| StreamError::Accept)?;
        self.classify(socket)
    }

    /// Attempts to accept an incoming connection within `timeout`.
    ///
    /// Returns `Ok(None)` if no connection arrives within `timeout`.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<StreamAccept>, StreamError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| StreamError::Accept)?;
        let start = std::time::Instant::now();
        loop {
            match self.listener.accept() {
                Ok((socket, _peer)) => {
                    let _ = self.listener.set_nonblocking(false);
                    let _ = socket.set_nonblocking(false);
                    return self.classify(socket).map(Some);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= timeout {
                        let _ = self.listener.set_nonblocking(false);
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => {
                    let _ = self.listener.set_nonblocking(false);
                    return Err(StreamError::Accept);
                }
            }
        }
    }

    fn classify(&self, socket: TcpStream) -> Result<StreamAccept, StreamError> {
        let mut transport =
            TcpFrameTransport::new(socket, &self.candidate_id, self.receive_deadline)
                .map_err(|_| StreamError::Accept)?;
        let preamble = transport.receive_frame().map_err(StreamError::Preamble)?;
        match StreamRendezvous::decode(&preamble)? {
            StreamRendezvous::Pairing => Ok(StreamAccept::Pairing(transport)),
            StreamRendezvous::Session(rendezvous_token) => Ok(StreamAccept::Session {
                rendezvous_token,
                transport,
            }),
        }
    }
}

/// Dials a listener and sends the preamble, as the proxy side does. Used by
/// loopback tests and by a future Windows-hosted proxy.
///
/// # Errors
///
/// Fails when no endpoint accepts the connection or the preamble cannot be
/// sent.
pub fn dial(
    endpoints: &[String],
    candidate_id: &str,
    receive_deadline: Duration,
    rendezvous: &StreamRendezvous,
) -> Result<TcpFrameTransport, StreamError> {
    let preamble = rendezvous.encode()?;
    for endpoint in endpoints {
        let Ok(socket) = TcpStream::connect(endpoint.as_str()) else {
            continue;
        };
        let mut transport = TcpFrameTransport::new(socket, candidate_id, receive_deadline)
            .map_err(|_| StreamError::Accept)?;
        transport
            .send_frame(&preamble)
            .map_err(StreamError::Preamble)?;
        return Ok(transport);
    }
    Err(StreamError::Unreachable)
}

/// Derives the Bonjour service instance name for a shared seed value.
///
/// Returns `"rf-"` concatenated with the lowercase 16-hex-digit (8-byte) prefix
/// of the SHA-256 digest of `value`.
#[must_use]
pub fn stream_rendezvous_name(value: &[u8]) -> String {
    use core::fmt::Write as _;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value);
    let mut out = String::with_capacity(19);
    out.push_str("rf-");
    for b in &digest[..8] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn parse_dns_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = 0;
    let mut jumps = 0;

    while offset < buf.len() {
        let len = *buf.get(offset)? as usize;
        if len == 0 {
            if !jumped {
                next_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if jumps > 10 {
                return None;
            }
            let b2 = *buf.get(offset + 1)? as usize;
            let ptr = ((len & 0x3F) << 8) | b2;
            if !jumped {
                next_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            continue;
        }
        offset += 1;
        let end = offset.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(buf.get(offset..end)?).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
    Some((labels.join("."), next_offset))
}

/// Discovers available stream transport endpoints via local mDNS.
///
/// Queries `_refineid-stream._tcp.local` on `224.0.0.251:5353` and returns
/// candidate `host:port` endpoints. If `service_name` is supplied, only
/// endpoints matching that service instance name (e.g. `rf-23142b280b566e12`)
/// are returned.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "mDNS packet assembly, socket polling, and DNS record parsing"
)]
#[allow(
    clippy::similar_names,
    reason = "DNS header fields an_count and ar_count are standard RFC 1035 names"
)]
pub fn discover_stream_endpoints(service_name: Option<&str>, timeout: Duration) -> Vec<String> {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::time::Instant;

    let target_service = service_name.map(|name| {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with("._refineid-stream._tcp.local") {
            lower
        } else {
            format!("{lower}._refineid-stream._tcp.local")
        }
    });

    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));

    let mut query = Vec::with_capacity(64);
    // Header: ID=0, Flags=0, Questions=1, Answer RRs=0, Authority RRs=0, Additional RRs=0
    query.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    // QNAME: _refineid-stream._tcp.local
    query.extend_from_slice(b"\x10_refineid-stream\x04_tcp\x05local\x00");
    // QTYPE: PTR (12), QCLASS: IN with QU unicast-response bit (0x8001)
    query.extend_from_slice(&[0x00, 0x0C, 0x80, 0x01]);

    let mdns_multicast = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
    if socket.send_to(&query, mdns_multicast).is_err() {
        return Vec::new();
    }

    let start = Instant::now();
    let mut srv_records: HashMap<String, (u16, String, Ipv4Addr)> = HashMap::new();
    let mut a_records: HashMap<String, Ipv4Addr> = HashMap::new();
    let mut buffer = [0u8; 4096];

    while start.elapsed() < timeout {
        let Ok((bytes_read, peer_addr)) = socket.recv_from(&mut buffer) else {
            if !srv_records.is_empty() {
                break;
            }
            continue;
        };
        let data = &buffer[..bytes_read];
        if data.len() < 12 {
            continue;
        }

        let qd_count = usize::from(u16::from_be_bytes([data[4], data[5]]));
        let an_count = usize::from(u16::from_be_bytes([data[6], data[7]]));
        let ns_count = usize::from(u16::from_be_bytes([data[8], data[9]]));
        let ar_count = usize::from(u16::from_be_bytes([data[10], data[11]]));
        let total_rr = an_count + ns_count + ar_count;

        let mut offset = 12;
        // Skip question section
        for _ in 0..qd_count {
            if let Some((_, next_off)) = parse_dns_name(data, offset) {
                offset = next_off + 4; // skip QTYPE + QCLASS
            } else {
                break;
            }
        }

        let peer_ip = match peer_addr {
            std::net::SocketAddr::V4(v4) => *v4.ip(),
            std::net::SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };

        // Parse Resource Records
        for _ in 0..total_rr {
            if offset >= data.len() {
                break;
            }
            let Some((rr_name, after_name)) = parse_dns_name(data, offset) else {
                break;
            };
            if after_name + 10 > data.len() {
                break;
            }
            let rtype = u16::from_be_bytes([data[after_name], data[after_name + 1]]);
            let rdlen = usize::from(u16::from_be_bytes([
                data[after_name + 8],
                data[after_name + 9],
            ]));
            let rdata_offset = after_name + 10;
            let next_rr = rdata_offset + rdlen;
            if next_rr > data.len() {
                break;
            }
            let rdata = &data[rdata_offset..next_rr];

            match rtype {
                // SRV
                33 if rdata.len() >= 6 => {
                    let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    if let Some((target_host, _)) = parse_dns_name(data, rdata_offset + 6) {
                        srv_records.insert(rr_name, (port, target_host, peer_ip));
                    }
                }
                // A
                1 if rdata.len() == 4 => {
                    let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                    a_records.insert(rr_name, ip);
                }
                _ => {}
            }
            offset = next_rr;
        }

        // If we found a matching service and resolved its IP, we can finish early
        if let Some(target) = &target_service
            && let Some((_port, host, peer_ip)) = srv_records.get(target)
            && (a_records.contains_key(host) || *peer_ip != Ipv4Addr::UNSPECIFIED)
        {
            break;
        }
    }

    let mut endpoints = Vec::new();
    for (name, (port, host, peer_ip)) in &srv_records {
        if let Some(target) = &target_service
            && name != target
        {
            continue;
        }
        if let Some(ip) = a_records.get(host) {
            endpoints.push(format!("{ip}:{port}"));
        } else if *peer_ip != Ipv4Addr::UNSPECIFIED {
            endpoints.push(format!("{peer_ip}:{port}"));
        }
        endpoints.push(format!("{host}:{port}"));
    }
    endpoints
}

/// Rejected stream-profile bytes, parameters, or connection steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// Structure, domain, type, or token length was not as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_STREAM_RENDEZVOUS_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
    /// Candidate carried no endpoint or more than [`MAX_STREAM_ENDPOINTS`].
    EndpointCount,
    /// An endpoint literal was empty or exceeded
    /// [`MAX_STREAM_ENDPOINT_BYTES`].
    EndpointLength,
    /// The listener address could not be bound or reported.
    Bind,
    /// A connection could not be accepted or wrapped.
    Accept,
    /// The preamble frame could not be moved.
    Preamble(TransportError),
    /// No advertised endpoint accepted the connection.
    Unreachable,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::time::Duration;

    use super::{
        MAX_STREAM_ENDPOINTS, StreamAccept, StreamError, StreamListener, StreamRendezvous, dial,
        stream_candidate_endpoints, stream_candidate_parameters,
    };
    use crate::ids::RendezvousToken;
    use crate::transport::FrameTransport;

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";

    fn token() -> RendezvousToken {
        RendezvousToken([0x5A; 16])
    }

    #[test]
    fn rendezvous_name_derives_expected_prefix() {
        assert_eq!(
            super::stream_rendezvous_name(b"hello"),
            "rf-2cf24dba5fb0a30e"
        );
    }

    #[test]
    fn preambles_round_trip_and_reject_foreign_purposes() {
        let pairing = StreamRendezvous::Pairing.encode().unwrap();
        assert_eq!(
            StreamRendezvous::decode(&pairing).unwrap(),
            StreamRendezvous::Pairing
        );
        let session = StreamRendezvous::Session(token()).encode().unwrap();
        assert_eq!(
            StreamRendezvous::decode(&session).unwrap(),
            StreamRendezvous::Session(token())
        );
        let oversized = vec![0u8; super::MAX_STREAM_RENDEZVOUS_FRAME + 1];
        assert_eq!(
            StreamRendezvous::decode(&oversized),
            Err(StreamError::Oversized)
        );
    }

    #[test]
    fn candidate_parameters_round_trip_and_bound() {
        let endpoints = vec!["192.0.2.10:47110".to_owned()];
        let parameters = stream_candidate_parameters(&endpoints).unwrap();
        assert_eq!(stream_candidate_endpoints(&parameters).unwrap(), endpoints);
        let excessive = vec!["192.0.2.10:47110".to_owned(); MAX_STREAM_ENDPOINTS + 1];
        assert_eq!(
            stream_candidate_parameters(&excessive),
            Err(StreamError::EndpointCount)
        );
    }

    #[test]
    fn listener_classifies_pairing_and_session_dials() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let endpoints = vec![format!("127.0.0.1:{port}")];

        let dial_endpoints = endpoints.clone();
        let dialer = std::thread::spawn(move || {
            dial(
                &dial_endpoints,
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Pairing,
            )
            .unwrap()
        });
        let accepted = listener.accept().unwrap();
        assert!(matches!(accepted, StreamAccept::Pairing(_)));
        drop(dialer.join().unwrap());

        let dialer = std::thread::spawn(move || {
            let mut transport = dial(
                &endpoints,
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Session(RendezvousToken([0x5A; 16])),
            )
            .unwrap();
            // Prove the channel survives the preamble in both directions.
            transport.send_frame(&[0x01, 0x02]).unwrap();
        });
        let accepted = listener.accept().unwrap();
        let StreamAccept::Session {
            rendezvous_token,
            mut transport,
        } = accepted
        else {
            panic!("expected a session accept");
        };
        assert_eq!(rendezvous_token, RendezvousToken([0x5A; 16]));
        assert_eq!(transport.receive_frame().unwrap(), vec![0x01, 0x02]);
        dialer.join().unwrap();
    }

    #[test]
    fn garbage_preambles_close_without_classification() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let dialer = std::thread::spawn(move || {
            let socket = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            let mut transport =
                crate::transport::TcpFrameTransport::new(socket, CANDIDATE, DEADLINE).unwrap();
            transport.send_frame(&[0xFF, 0x00, 0x11]).unwrap();
        });
        assert!(matches!(listener.accept(), Err(StreamError::Malformed)));
        dialer.join().unwrap();
    }
}
