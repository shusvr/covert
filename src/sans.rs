#![allow(dead_code, unused_variables)]

use std::{
    collections::VecDeque,
    time::{Duration, Instant, SystemTime},
};

use bytes::{Bytes, BytesMut};

use crate::{
    Key, Result,
    codec::{self, Data, DataFlags, Packet, PacketLayout},
    config::Liveness,
    crypto::{self, Cipher, Initiating},
};

enum State {
    Idle,
    Established {
        cipher: Cipher,
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
    remote_pk: Option<Key>,
    psk: Option<Key>,
    queue: VecDeque<Vec<u8>>,
    received: BytesMut,
    state: State,
    outbound: VecDeque<Packet>,
    decrypted: VecDeque<Vec<u8>>,
    pending: Option<PendingInitiation>,
    liveness: Liveness,
    layout: PacketLayout,
}

pub struct PendingInitiation {
    pub initiation: Initiating,
    pub public_key: Key,
    pub timestamp: u64,
}

impl Tunnel {
    pub fn new(
        layout: PacketLayout,
        local_sk: Key,
        liveness: Liveness,
        remote_pk: Option<Key>,
        psk: Option<Key>,
    ) -> Result<Self> {
        let state = if let Some(remote_pk) = remote_pk {
            let initiated = crypto::initiate(&local_sk, &remote_pk, timestamp(), index())?;
            State::Initiated {
                initiated: initiated,
                last_initiated: None,
            }
        } else {
            State::Idle
        };

        Ok(Self {
            layout,
            local_sk,
            remote_pk,
            state,
            psk,
            liveness,
            queue: Default::default(),
            decrypted: Default::default(),
            outbound: Default::default(),
            received: BytesMut::new(),
            pending: None,
        })
    }

    pub fn push_packet(&mut self, packet: &[u8]) {
        let mut buf = Vec::with_capacity(packet.len() + 16);
        buf.extend_from_slice(packet);
        self.queue.push_back(buf);
    }

    pub fn write_incoming(&mut self, packet: &[u8]) {
        self.received.extend_from_slice(packet);
    }

    fn initiate_expired(&mut self) -> Result<()> {
        let initiated = crypto::initiate(
            &self.local_sk,
            // if the state has been established we for sure know the remote pk
            &self.remote_pk.unwrap(),
            timestamp(),
            index(),
        )?;
        self.state = State::Initiated {
            initiated: initiated,
            last_initiated: None,
        };

        Ok(())
    }

    pub fn approve_pending(&mut self, psk: Option<Key>, liveness: Liveness) -> Result<()> {
        let Some(PendingInitiation {
            initiation,
            public_key,
            timestamp,
        }) = self.pending.take()
        else {
            return Ok(());
        };

        self.remote_pk = Some(public_key);
        self.psk = psk;
        self.liveness = liveness;

        let (reply, cipher) = crypto::post_reply(
            &public_key,
            psk.as_ref(),
            initiation.sender_idx,
            &initiation,
        )?;
        self.establish(cipher, initiation.sender_idx, timestamp);
        self.outbound.push_back(Packet::Reply(reply));

        Ok(())
    }

    pub fn reject_pending(&mut self) {
        self.pending = None;
    }

    fn process_received(&mut self) -> Result<Option<&PendingInitiation>> {
        while let Some(packet) = codec::parse(&mut self.received, &self.layout).transpose()? {
            match packet {
                Packet::Initiating(initiating) => {
                    let (public_key, timestamp) = crypto::pre_reply(&self.local_sk, &initiating)?;

                    if !matches!(
                        self.state,
                        State::Established { timestamp: old, .. } if old >= timestamp
                    ) {
                        self.pending = Some(PendingInitiation {
                            initiation: initiating,
                            public_key,
                            timestamp,
                        });
                        return Ok(self.pending.as_ref());
                    }
                }
                Packet::Reply(replying) => {
                    if let State::Initiated { initiated, .. } = &self.state
                        && initiated.sender_idx == replying.receiver_idx
                    {
                        let cipher = crypto::finish(
                            &self.local_sk,
                            self.psk.as_ref(),
                            initiated,
                            &replying,
                        )?;
                        self.establish(cipher, replying.sender_idx, 0);
                    }
                }
                Packet::Data(Data {
                    receiver_idx,
                    flags,
                    counter,
                    ciphertext,
                }) => {
                    let now = Instant::now();
                    if let State::Established {
                        cipher,
                        receiver_idx,
                        established,
                        last_seen: seen,
                        next_ka,
                        timestamp: _,
                    } = &mut self.state
                    {
                        if self.liveness.has_expired(now - *established, now - *seen) {
                            // connection has expired
                            self.initiate_expired()?;
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
        }

        Ok(None)
    }

    fn establish(&mut self, cipher: Cipher, receiver_idx: u32, timestamp: u64) {
        let now = Instant::now();
        self.state = State::Established {
            cipher,
            timestamp,
            receiver_idx,
            established: now,
            last_seen: now,
            next_ka: now + Duration::from_millis(self.liveness.next_ka()),
        };
    }

    pub fn process_new_packets(&mut self) -> Result<Option<&PendingInitiation>> {
        while let Some(x) = self.process_received()? {
            return Ok(Some(x));
        }

        match &mut self.state {
            State::Idle => {}
            State::Established {
                cipher,
                receiver_idx,
                established,
                last_seen: seen,
                next_ka,
                timestamp: _,
            } => {
                let now = Instant::now();

                if self.liveness.has_expired(now - *established, now - *seen) {
                    // conn has expired
                    self.initiate_expired()?;
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
                            &self.remote_pk.unwrap(),
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
                if last_initiated.is_none_or(|x| (now - x) > Duration::from_secs(10)) {}
            }
        };

        Ok(None)
    }

    pub fn read_outbound(&mut self) -> Result<Option<Bytes>> {
        self.outbound
            .pop_front()
            .map(|p| {
                let mut buf = BytesMut::new();
                codec::append(&mut buf, p, &self.layout)?;
                Ok(buf.freeze())
            })
            .transpose()
    }

    pub fn read_packet(&mut self) -> Option<Vec<u8>> {
        self.decrypted.pop_front()
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
