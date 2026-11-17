use std::{
    collections::VecDeque,
    time::{Duration, Instant, SystemTime},
};

use bytes::{Bytes, BytesMut};

use crate::{
    codec::{self, Data, DataFlags, Packet, PacketLayout},
    crypto::{self, Cipher, Initiating, Key},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Codec: {0}")]
    Codec(#[from] codec::Error),
    #[error("Crypto error")]
    Crypto(#[from] aws_lc_rs::error::Unspecified),
}

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
pub struct Liveness {
    pub timeout: u64,
    pub max_age: u64,
    pub ka_delay: u32,
    pub ka_jitter: u32,
}

impl Liveness {
    pub fn has_expired(&self, since_established: Duration, since_last_seen: Duration) -> bool {
        (since_established > Duration::from_secs(self.max_age) && self.max_age != 0)
            || (since_last_seen > Duration::from_secs(self.timeout) && self.timeout != 0)
    }

    pub fn next_ka(&self) -> u64 {
        ((self.ka_delay as f64 + (self.ka_jitter as f64 * (fastrand::f64() * 2.0 - 1.0))) * 1000.0)
            .max(1000.0) as u64
    }
}

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
        let (public_key, timestamp) = crypto::pre_reply(local_sk, &initiation)?;
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
    }

    pub fn write_incoming(&mut self, packet: &[u8]) {
        self.received.extend_from_slice(packet);
    }

    /// Start a handshake, retaining queued plaintext for the new session.
    pub fn initiate(&mut self) -> Result<()> {
        let initiated = crypto::initiate(&self.local_sk, &self.remote_pk, timestamp(), index())?;
        self.state = State::Initiated {
            initiated,
            last_initiated: None,
        };

        Ok(())
    }

    fn process_received(&mut self) -> Result<()> {
        while let Some(packet) = codec::parse(&mut self.received, &self.layout).transpose()? {
            self.process_incoming_packet(packet)?;
        }
        Ok(())
    }

    /// Process an already decoded packet without buffering or parsing its bytes.
    /// Call `process_new_packets` afterward to handle outgoing work.
    pub fn process_incoming_packet(&mut self, packet: Packet) -> Result<()> {
        match packet {
            Packet::Initiating(initiating) => {
                let decoded = DecodedInitiation::decode(&self.local_sk, initiating)?;
                self.process_initiation(decoded)?;
            }
            Packet::Reply(replying) => {
                if let State::Initiated { initiated, .. } = &self.state
                    && initiated.sender_idx == replying.receiver_idx
                {
                    let cipher =
                        crypto::finish(&self.local_sk, self.psk.as_ref(), initiated, &replying)?;
                    let local_idx = initiated.sender_idx;
                    self.establish(cipher, local_idx, replying.sender_idx, 0);
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
                        return Ok(());
                    }
                    if self.liveness.has_expired(now - *established, now - *seen) {
                        // connection has expired
                        self.initiate()?;
                    } else {
                        // conn is live, decrypt

                        let plaintext = cipher.decrypt(counter, ciphertext)?;
                        if !flags.contains(DataFlags::JUNK) {
                            self.decrypted.push_back(plaintext);
                        }
                        *seen = now;
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply a decoded initiation without repeating its cryptographic decoding.
    pub fn process_initiation(&mut self, decoded: DecodedInitiation) -> Result<()> {
        if decoded.public_key != self.remote_pk {
            return Ok(());
        }
        if matches!(self.state, State::Initiated { .. }) {
            let local_public_key =
                crypto::pk_to_bytes(&crypto::to_sk(&self.local_sk).compute_public_key()?);
            // For competing handshakes, the smaller static public key initiates.
            if local_public_key < self.remote_pk {
                return Ok(());
            }
        }
        if matches!(
            self.state,
            State::Established { timestamp: old, .. } if old >= decoded.timestamp
        ) {
            return Ok(());
        }
        let local_idx = index();
        let (reply, cipher) = crypto::post_reply(
            &self.remote_pk,
            self.psk.as_ref(),
            local_idx,
            &decoded.initiation,
        )?;
        self.outbound
            .retain(|packet| !matches!(packet, Packet::Initiating(_)));
        self.establish(
            cipher,
            local_idx,
            decoded.initiation.sender_idx,
            decoded.timestamp,
        );
        self.outbound.push_back(Packet::Reply(reply));
        Ok(())
    }

    fn establish(&mut self, cipher: Cipher, local_idx: u32, receiver_idx: u32, timestamp: u64) {
        let now = Instant::now();
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

    pub fn process_new_packets(&mut self) -> Result<()> {
        self.process_received()?;

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
                    // conn has expired
                    self.initiate()?;
                } else {
                    // conn is live, encrypt

                    let mut added = false;
                    while let Some(packet) = self.queue.pop_front() {
                        let (counter, ciphertext) = cipher.encrypt(packet)?;
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
                        let (counter, ciphertext) = cipher.encrypt(Vec::with_capacity(16))?;
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
                        // refresh initiation

                        let initiating = crypto::initiate(
                            &self.local_sk,
                            &self.remote_pk,
                            timestamp(),
                            index(),
                        )?;
                        self.outbound
                            .push_back(Packet::Initiating(initiating.clone()));
                        *initiated = initiating;
                        *last_initiated = Some(now);
                    }
                    Some(_) => {}
                    None => {
                        // our first time, send as is
                        self.outbound
                            .push_back(Packet::Initiating(initiated.clone()));
                        *last_initiated = Some(now);
                    }
                }
            }
        };

        Ok(())
    }

    pub fn read_outbound(&mut self) -> Result<Option<Bytes>> {
        self.read_outbound_packet()
            .map(|p| {
                let mut buf = BytesMut::new();
                codec::append(&mut buf, p, &self.layout)?;
                Ok(buf.freeze())
            })
            .transpose()
    }

    pub fn read_outbound_packet(&mut self) -> Option<Packet> {
        self.outbound.pop_front()
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
mod tests;
