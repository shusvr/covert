use std::sync::atomic::{AtomicU64, Ordering};

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce},
    agreement::{
        self as ka, EphemeralPrivateKey, ParsedPublicKey, PrivateKey, PublicKey, UnparsedPublicKey,
        X25519,
    },
    digest::{Context as DigestContext, SHA256},
    encoding::{AsBigEndian, Curve25519SeedBin},
    error::Unspecified,
    hkdf::{self, HKDF_SHA256},
    rand::SystemRandom,
};

pub type Key = [u8; 32];
pub type SealedKey = [u8; 48];
pub type SealedTimestamp = [u8; 24];

#[cfg(test)]
mod tests;

pub fn random_sk() -> Result<PrivateKey, Unspecified> {
    PrivateKey::generate(&X25519)
}

pub fn to_sk(k: &Key) -> PrivateKey {
    PrivateKey::from_private_key(&X25519, k).unwrap()
}

pub fn to_pk(k: &Key) -> ParsedPublicKey {
    UnparsedPublicKey::new(&X25519, k).try_into().unwrap()
}

pub fn pk_to_bytes(pk: &PublicKey) -> Key {
    pk.as_ref().try_into().unwrap()
}

pub fn sk_to_bytes(sk: &PrivateKey) -> Key {
    let seed: Curve25519SeedBin = sk.as_be_bytes().unwrap();
    seed.as_ref().try_into().unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initiating {
    pub enc_ts: SealedTimestamp,
    pub sender_idx: u32,
    pub enc_pub_key: SealedKey,
    pub ephemeral: Key,
}

// Hash canonical fields rather than layout bytes, masks or random padding.
// The encrypted timestamp authenticates itself through its existing AEAD tag,
// so it must not be included in its own AAD (which would be circular).
fn initiation_aad(ephemeral: &Key, enc_pub_key: &SealedKey, sender_idx: u32) -> [u8; 32] {
    let mut hash = DigestContext::new(&SHA256);
    hash.update(b"covert-initiation-v1");
    hash.update(ephemeral);
    hash.update(enc_pub_key);
    hash.update(&sender_idx.to_be_bytes());
    hash.finish().as_ref().try_into().unwrap()
}

pub fn initiate(
    local_sk: &Key,
    remote_pk: &Key,
    timestamp: u64,
    sender_idx: u32,
) -> Result<Initiating, Unspecified> {
    let remote_pk = to_pk(remote_pk);
    let local_sk = to_sk(local_sk);
    let rng = SystemRandom::new();

    let esk = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let epk = esk.compute_public_key()?;

    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree_ephemeral(esk, remote_pk, Unspecified, |sm| Ok(salt.extract(sm)))?;
    let okm = prk.expand(&[b"for-hs"], &aead::CHACHA20_POLY1305)?;
    let aes = LessSafeKey::new(aead::UnboundKey::from(okm));

    // 0 nonce is indeed unique for a key we just computed since its derived from a random ephemeral
    let mut inout = [0; 48];
    inout[..32].copy_from_slice(local_sk.compute_public_key()?.as_ref());

    let tag = aes.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key([0; _]),
        Aad::empty(),
        &mut inout[..32],
    )?;
    inout[32..].copy_from_slice(tag.as_ref());

    let aad = initiation_aad(&pk_to_bytes(&epk), &inout, sender_idx);
    let mut enc_ts = [0; 24];
    enc_ts[..8].copy_from_slice(&timestamp.to_be_bytes());
    let mut nonce = [0; 12];
    nonce[11] = 1;
    let tag = aes.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut enc_ts[..8],
    )?;
    enc_ts[8..].copy_from_slice(tag.as_ref());

    Ok(Initiating {
        enc_ts,
        enc_pub_key: inout.try_into().unwrap(),
        ephemeral: pk_to_bytes(&epk),
        sender_idx,
    })
}

pub fn pre_reply(local_sk: &Key, initiating: &Initiating) -> Result<(Key, u64), Unspecified> {
    let local_sk = to_sk(local_sk);
    let Initiating {
        mut enc_pub_key,
        ephemeral,
        mut enc_ts,
        sender_idx,
    } = *initiating;
    let aad = initiation_aad(&ephemeral, &enc_pub_key, sender_idx);
    let remote_epk = to_pk(&ephemeral);

    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree(
        &local_sk,
        remote_epk,
        Unspecified,
        |km| Ok(salt.extract(km)),
    )?;
    let okm = prk.expand(&[b"for-hs"], &aead::CHACHA20_POLY1305)?;
    let cipher = LessSafeKey::new(aead::UnboundKey::from(okm));

    let mut nonce = [0; 12];
    nonce[11] = 1;
    let timestamp = cipher.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut enc_ts,
    )?;
    let timestamp = u64::from_be_bytes(timestamp.try_into().map_err(|_| Unspecified)?);

    let pub_key = &*cipher.open_within(
        Nonce::assume_unique_for_key([0; _]),
        Aad::empty(),
        &mut enc_pub_key,
        0..,
    )?;

    let parsed: ParsedPublicKey = UnparsedPublicKey::new(&X25519, pub_key).try_into().unwrap();

    let mut key = Key::default();
    key.copy_from_slice(parsed.as_ref());
    Ok((key, timestamp))
}

#[derive(Debug, Clone, Copy)]
pub struct Replying {
    pub eph: Key,
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub auth_tag: [u8; 16],
}

// The reply is bound to the entire original initiation, not just its index.
fn reply_aad(initiating: &Initiating, replying: &Replying) -> [u8; 32] {
    let mut hash = DigestContext::new(&SHA256);
    hash.update(b"covert-reply-v1");
    hash.update(&initiation_aad(
        &initiating.ephemeral,
        &initiating.enc_pub_key,
        initiating.sender_idx,
    ));
    hash.update(&initiating.enc_ts);
    hash.update(&replying.eph);
    hash.update(&replying.sender_idx.to_be_bytes());
    hash.update(&replying.receiver_idx.to_be_bytes());
    hash.finish().as_ref().try_into().unwrap()
}

pub fn post_reply(
    remote_pk: &Key,
    pre_shared_key: Option<&Key>,
    sender_idx: u32,
    initiating: &Initiating,
) -> Result<(Replying, Cipher), Unspecified> {
    let remote_pk = to_pk(remote_pk);

    let esk = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())?;
    let epk = esk.compute_public_key()?;
    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree_ephemeral(esk, remote_pk, Unspecified, |km| Ok(salt.extract(km)))?;

    let mut replying = Replying {
        eph: pk_to_bytes(&epk),
        sender_idx,
        receiver_idx: initiating.sender_idx,
        auth_tag: [0; 16],
    };
    let aad = reply_aad(initiating, &replying);
    let psk = pre_shared_key.map(|x| &x[..]).unwrap_or(b"");
    // Bind session keys to this handshake too, avoiding key reuse if a reply
    // ephemeral is ever reused with a different initiation.
    let info = [psk, b"for-session", &aad];
    let okm = prk.expand(&info, &aead::CHACHA20_POLY1305)?;
    let key = LessSafeKey::new(aead::UnboundKey::from(okm));
    // Empty plaintext yields only a tag. Nonce zero is reserved for this;
    // data starts at counter 1 and uses distinct role bytes.
    let tag = key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::from(&aad),
        &mut [],
    )?;
    replying.auth_tag.copy_from_slice(tag.as_ref());
    Ok((replying, Cipher::new(key, false)))
}

pub fn finish(
    local_sk: &Key,
    pre_shared_key: Option<&Key>,
    initiating: &Initiating,
    replying: &Replying,
) -> Result<Cipher, Unspecified> {
    let local_sk = to_sk(local_sk);
    if replying.receiver_idx != initiating.sender_idx {
        return Err(Unspecified);
    }
    let aad = reply_aad(initiating, replying);
    let remote_epk = UnparsedPublicKey::new(&X25519, &replying.eph);

    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree(
        &local_sk,
        remote_epk,
        Unspecified,
        |km| Ok(salt.extract(km)),
    )?;
    let psk = pre_shared_key.map(|x| &x[..]).unwrap_or(b"");
    let info = [psk, b"for-session", &aad];
    let okm = prk.expand(&info, &aead::CHACHA20_POLY1305)?;
    let key = LessSafeKey::new(aead::UnboundKey::from(okm));

    let mut tag = replying.auth_tag;
    key.open_in_place(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::from(&aad),
        &mut tag,
    )?;
    Ok(Cipher::new(key, true))
}

const MAX_NONCE_LAG: u64 = 200;

pub struct Cipher {
    encrypt_counter: AtomicU64,
    decrypt_counter: AtomicU64,
    key: LessSafeKey,
    is_initiator: bool,
}

impl Cipher {
    /// Peers sharing a key must use opposite roles to avoid nonce reuse.
    pub fn new(key: LessSafeKey, is_initiator: bool) -> Self {
        Self {
            encrypt_counter: AtomicU64::new(1),
            decrypt_counter: AtomicU64::new(0),
            key,
            is_initiator,
        }
    }

    fn nonce(value: u64, is_initiator: bool) -> Nonce {
        let mut bytes = [0; 12];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        bytes[11] = if is_initiator { 1 } else { 2 };
        Nonce::assume_unique_for_key(bytes)
    }

    pub fn encrypt(&self, mut data: Vec<u8>) -> Result<(u64, Vec<u8>), Unspecified> {
        let value = self
            .encrypt_counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Unspecified)?;
        self.key.seal_in_place_append_tag(
            Self::nonce(value, self.is_initiator),
            Aad::empty(),
            &mut data,
        )?;
        Ok((value, data))
    }

    pub fn decrypt(&self, nonce: u64, mut ciphertext: Vec<u8>) -> Result<Vec<u8>, Unspecified> {
        if nonce == 0 {
            return Err(Unspecified);
        }
        let len = self
            .key
            .open_in_place(
                Self::nonce(nonce, !self.is_initiator),
                Aad::empty(),
                &mut ciphertext,
            )?
            .len();
        ciphertext.truncate(len);
        // repeats within the allowed lag are whatever
        let highest = self.decrypt_counter.fetch_max(nonce, Ordering::Relaxed);
        if highest.saturating_sub(nonce) > MAX_NONCE_LAG {
            return Err(Unspecified);
        }
        Ok(ciphertext)
    }
}
