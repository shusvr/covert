//! Transport-independent tunnel state machine.
//!
//! Emits `tracing` events under `covert::sans`: info for established sessions,
//! debug for handshakes/expiry/rejections, trace for packet metadata/keepalives,
//! and warn for local processing failures. Keys and packet contents are omitted.
//! The host application is responsible for installing a tracing subscriber.

use std::{
    collections::VecDeque,
    time::{Duration, Instant, SystemTime},
};

use crate::Result;
use bytes::{Bytes, BytesMut};
use tracing::{debug, info, trace, warn};

use crate::{
    codec::{self, Data, DataFlags, Packet, PacketLayout},
    config::Liveness,
    crypto::{self, Cipher, Initiating, Key},
};

enum State {
    Idle,
    Established {
        cipher: Cipher,
        local_idx: u32,
        receiver_idx: u32,
        timestamp: u64,
        established: Instant,
        last_seen: Instant,
        next_ka: Instant,
    },
    Initiated {
        initiated: Initiating,
        last_initiated: Option<Instant>,
    },
}

pub struct Tunnel {
    local_sk: Key,
    remote_pk: Key,
    psk: Option<Key>,
    queue: VecDeque<Vec<u8>>,
    received: BytesMut,
    state: State,
    outbound: VecDeque<Packet>,
    decrypted: VecDeque<Vec<u8>>,
    liveness: Liveness,
    layout: PacketLayout,
}

pub struct DecodedInitiation {
    pub initiation: Initiating,
    pub public_key: Key,
    pub timestamp: u64,
}

impl DecodedInitiation {
    /// Decode the peer identity before choosing which tunnel should handle it.
    pub fn decode(local_sk: &Key, initiation: Initiating) -> Result<Self> {
        let (public_key, timestamp) = crypto::pre_reply(local_sk, &initiation).inspect_err(|err| {
            debug!(sender_idx = initiation.sender_idx, %err, "Rejected initiation: authentication failed");
        })?;
        Ok(Self {
            initiation,
            public_key,
            timestamp,
        })
    }
}

impl Tunnel {
    pub fn new(
        layout: PacketLayout,
        local_sk: Key,
        liveness: Liveness,
        remote_pk: Key,
        psk: Option<Key>,
    ) -> Self {
        debug!(
            timeout = liveness.timeout,
            max_age = liveness.max_age,
            keepalive = liveness.ka_delay,
            keepalive_jitter = liveness.ka_jitter,
            "Created idle tunnel"
        );
        Self {
            layout,
            local_sk,
            remote_pk,
            state: State::Idle,
            psk,
            liveness,
            queue: Default::default(),
            decrypted: Default::default(),
            outbound: Default::default(),
            received: BytesMut::new(),
        }
    }

    pub fn push_packet(&mut self, packet: &[u8]) {
        let mut buf = Vec::with_capacity(packet.len() + 16);
        buf.extend_from_slice(packet);
        self.queue.push_back(buf);
        trace!(
            packet_len = packet.len(),
            queued = self.queue.len(),
            "Queued plaintext packet"
        );
    }

    pub fn write_incoming(&mut self, packet: &[u8]) {
        self.received.extend_from_slice(packet);
        trace!(
            input_len = packet.len(),
            buffered = self.received.len(),
            "Buffered incoming bytes"
        );
    }

    /// Start a handshake, retaining queued plaintext for the new session.
    pub fn initiate(&mut self) -> Result<()> {
        let initiated = crypto::initiate(&self.local_sk, &self.remote_pk, timestamp(), index())
            .inspect_err(|err| warn!(%err, "Failed to create initiation"))?;
        debug!(
            local_idx = initiated.sender_idx,
            queued = self.queue.len(),
            "Starting handshake"
        );
        self.state = State::Initiated {
            initiated,
            last_initiated: None,
        };

        Ok(())
    }

    fn process_received(&mut self) -> Result<()> {
        while let Some(packet) = codec::parse(&mut self.received, &self.layout)
            .transpose()
            .inspect_err(|err| debug!(%err, "Rejected buffered packet: codec error"))?
        {
            self.process_incoming_packet(packet)?;
        }
        Ok(())
    }

    /// Process an already decoded packet without buffering or parsing its bytes.
    /// Call `process_new_packets` afterward to handle outgoing work.
    pub fn process_incoming_packet(&mut self, packet: Packet) -> Result<()> {
        self.process_incoming_packet_accepted(packet).map(|_| ())
    }

    /// True only when this packet was authenticated and accepted by the session.
    pub(crate) fn process_incoming_packet_accepted(&mut self, packet: Packet) -> Result<bool> {
        match packet {
            Packet::Initiating(initiating) => {
                let decoded = DecodedInitiation::decode(&self.local_sk, initiating)?;
                return self.accept_initiation(decoded);
            }
            Packet::Reply(replying) => {
                if let State::Initiated { initiated, .. } = &self.state
                    && initiated.sender_idx == replying.receiver_idx
                {
                    let cipher = crypto::finish(&self.local_sk, self.psk.as_ref(), initiated, &replying)
                        .inspect_err(|err| debug!(local_idx = initiated.sender_idx,
                            sender_idx = replying.sender_idx, %err, "Rejected reply: authentication failed"))?;
                    let local_idx = initiated.sender_idx;
                    self.establish(cipher, local_idx, replying.sender_idx, 0);
                    return Ok(true);
                } else {
                    debug!(receiver_idx = replying.receiver_idx, sender_idx = replying.sender_idx,
                        local_idx = ?self.local_index(), "Ignored reply: no matching initiation");
                }
            }
            Packet::Data(Data {
                receiver_idx: incoming_idx,
                flags,
                counter,
                ciphertext,
            }) => {
                let now = Instant::now();
                if let State::Established {
                    cipher,
                    local_idx,
                    established,
                    last_seen: seen,
                    ..
                } = &mut self.state
                {
                    if incoming_idx != *local_idx {
                        trace!(
                            receiver_idx = incoming_idx,
                            local_idx = *local_idx,
                            "Ignored data: receiver index mismatch"
                        );
                        return Ok(false);
                    }
                    if self.liveness.has_expired(now - *established, now - *seen) {
                        debug!(
                            local_idx = *local_idx,
                            age_secs = (now - *established).as_secs(),
                            idle_secs = (now - *seen).as_secs(),
                            "Session expired on incoming data; rekeying"
                        );
                        self.initiate()?;
                    } else {
                        // conn is live, decrypt

                        let plaintext = cipher.decrypt(counter, ciphertext).inspect_err(|err| {
                            debug!(local_idx = *local_idx, counter, %err,
                                "Rejected data: authentication or counter validation failed");
                        })?;
                        let keepalive = flags.contains(DataFlags::JUNK);
                        trace!(
                            local_idx = *local_idx,
                            counter,
                            keepalive,
                            plaintext_len = plaintext.len(),
                            "Authenticated incoming data"
                        );
                        if !keepalive {
                            self.decrypted.push_back(plaintext);
                        }
                        *seen = now;
                        return Ok(true);
                    }
                } else {
                    trace!(
                        receiver_idx = incoming_idx,
                        "Ignored data: session not established"
                    );
                }
            }
        }
        Ok(false)
    }

    /// Apply a decoded initiation without repeating its cryptographic decoding.
    /// Returns true when accepted, or false when ignored.
    pub fn accept_initiation(&mut self, decoded: DecodedInitiation) -> Result<bool> {
        if decoded.public_key != self.remote_pk {
            debug!(
                sender_idx = decoded.initiation.sender_idx,
                "Ignored initiation: peer identity mismatch"
            );
            return Ok(false);
        }
        if matches!(self.state, State::Initiated { .. }) {
            let local_public_key =
                crypto::pk_to_bytes(&crypto::to_sk(&self.local_sk).compute_public_key()?);
            // For competing handshakes, the smaller static public key initiates.
            if local_public_key < self.remote_pk {
                debug!(
                    sender_idx = decoded.initiation.sender_idx,
                    "Ignored competing initiation: retaining initiator role"
                );
                return Ok(false);
            }
        }
        if matches!(
            self.state,
            State::Established { timestamp: old, .. } if old >= decoded.timestamp
        ) {
            debug!(
                sender_idx = decoded.initiation.sender_idx,
                "Ignored initiation: stale or replayed timestamp"
            );
            return Ok(false);
        }
        debug!(
            sender_idx = decoded.initiation.sender_idx,
            "Accepted initiation; replying"
        );
        let local_idx = index();
        let (reply, cipher) = crypto::post_reply(
            &self.remote_pk,
            self.psk.as_ref(),
            local_idx,
            &decoded.initiation,
        )
        .inspect_err(|err| warn!(local_idx, %err, "Failed to create handshake reply"))?;
        self.outbound
            .retain(|packet| !matches!(packet, Packet::Initiating(_)));
        self.establish(
            cipher,
            local_idx,
            decoded.initiation.sender_idx,
            decoded.timestamp,
        );
        self.outbound.push_back(Packet::Reply(reply));
        debug!(local_idx, "Queued handshake reply");
        Ok(true)
    }

    fn establish(&mut self, cipher: Cipher, local_idx: u32, receiver_idx: u32, timestamp: u64) {
        let now = Instant::now();
        info!(
            local_idx,
            receiver_idx,
            queued = self.queue.len(),
            "Session established"
        );
        self.state = State::Established {
            cipher,
            local_idx,
            timestamp,
            receiver_idx,
            established: now,
            last_seen: now,
            next_ka: now + Duration::from_millis(self.liveness.next_ka()),
        };
    }

    pub fn process_new_packets(&mut self, flush_on_err: bool) -> Result<()> {
        let result = self.process_received();
        if result.is_err() && flush_on_err {
            self.received.clear();
        }

        match &mut self.state {
            State::Idle => {}
            State::Established {
                cipher,
                receiver_idx,
                established,
                last_seen: seen,
                next_ka,
                ..
            } => {
                let now = Instant::now();

                if self.liveness.has_expired(now - *established, now - *seen) {
                    debug!(
                        receiver_idx = *receiver_idx,
                        age_secs = (now - *established).as_secs(),
                        idle_secs = (now - *seen).as_secs(),
                        "Session expired during maintenance; rekeying"
                    );
                    self.initiate()?;
                } else {
                    // conn is live, encrypt

                    let mut added = false;
                    while let Some(packet) = self.queue.pop_front() {
                        let plaintext_len = packet.len();
                        let (counter, ciphertext) = cipher
                            .encrypt(packet)
                            .inspect_err(|err| warn!(%err, "Failed to encrypt queued packet"))?;
                        trace!(
                            receiver_idx = *receiver_idx,
                            counter, plaintext_len, "Encrypted outgoing data"
                        );
                        let data = Data {
                            receiver_idx: *receiver_idx,
                            flags: DataFlags::empty(),
                            counter,
                            ciphertext,
                        };
                        self.outbound.push_back(Packet::Data(data));
                        added = true;
                    }

                    // if we aren't sending data, see if we need to send ka
                    if !added && now > *next_ka {
                        let (counter, ciphertext) = cipher
                            .encrypt(Vec::with_capacity(16))
                            .inspect_err(|err| warn!(%err, "Failed to encrypt keepalive"))?;
                        trace!(receiver_idx = *receiver_idx, counter, "Queued keepalive");
                        let data = Data {
                            receiver_idx: *receiver_idx,
                            flags: DataFlags::JUNK,
                            counter,
                            ciphertext,
                        };
                        self.outbound.push_back(Packet::Data(data));
                        *next_ka = now + Duration::from_millis(self.liveness.next_ka());
                    } else if added {
                        *next_ka = now + Duration::from_millis(self.liveness.next_ka());
                    }
                }
            }
            State::Initiated {
                initiated,
                last_initiated,
            } => {
                let now = Instant::now();
                match last_initiated {
                    Some(last) if now - *last > Duration::from_secs(10) => {
                        debug!(
                            local_idx = initiated.sender_idx,
                            "Handshake retry timer expired"
                        );
                        let initiating =
                            crypto::initiate(&self.local_sk, &self.remote_pk, timestamp(), index())
                                .inspect_err(|err| warn!(%err, "Failed to refresh initiation"))?;
                        debug!(
                            local_idx = initiating.sender_idx,
                            "Queued refreshed initiation"
                        );
                        self.outbound
                            .push_back(Packet::Initiating(initiating.clone()));
                        *initiated = initiating;
                        *last_initiated = Some(now);
                    }
                    Some(_) => {}
                    None => {
                        debug!(local_idx = initiated.sender_idx, "Queued initial handshake");
                        self.outbound
                            .push_back(Packet::Initiating(initiated.clone()));
                        *last_initiated = Some(now);
                    }
                }
            }
        };

        result
    }

    pub fn read_outbound(&mut self) -> Result<Option<Bytes>> {
        self.read_outbound_packet()
            .map(|p| {
                let mut buf = BytesMut::new();
                codec::append(&mut buf, p, &self.layout)
                    .inspect_err(|err| warn!(%err, "Failed to encode outbound packet"))?;
                Ok(buf.freeze())
            })
            .transpose()
    }

    pub fn read_outbound_packet(&mut self) -> Option<Packet> {
        self.outbound.pop_front()
    }

    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    pub fn read_packet(&mut self) -> Option<Vec<u8>> {
        self.decrypted.pop_front()
    }

    /// Our index, used by datagram adapters to dispatch replies and data.
    pub fn local_index(&self) -> Option<u32> {
        match &self.state {
            State::Idle => None,
            State::Initiated { initiated, .. } => Some(initiated.sender_idx),
            State::Established { local_idx, .. } => Some(*local_idx),
        }
    }

    pub fn established_at(&self) -> Option<Instant> {
        match &self.state {
            State::Established { established, .. } => Some(*established),
            _ => None,
        }
    }

    pub fn is_live(&self) -> bool {
        match &self.state {
            State::Established {
                established,
                last_seen,
                ..
            } => !self
                .liveness
                .has_expired(established.elapsed(), last_seen.elapsed()),
            _ => false,
        }
    }
}

fn index() -> u32 {
    fastrand::u32(..)
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
#[path = "./tests/sans.rs"]
mod tests;
