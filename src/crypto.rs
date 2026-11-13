use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Key, SealedKey, SealedTimestamp};
use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce},
    agreement::{
        self as ka, EphemeralPrivateKey, ParsedPublicKey, PrivateKey, PublicKey, UnparsedPublicKey,
        X25519,
    },
    encoding::{AsBigEndian, Curve25519SeedBin},
    error::Unspecified,
    hkdf::{self, HKDF_SHA256},
    rand::SystemRandom,
};

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

#[derive(Debug, Clone)]
pub struct Initiating {
    pub(crate) enc_ts: SealedTimestamp,
    pub(crate) sender_idx: u32,
    pub(crate) enc_pub_key: SealedKey,
    pub(crate) ephemeral: Key,
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

    let mut enc_ts = [0; 24];
    enc_ts[..8].copy_from_slice(&timestamp.to_be_bytes());
    let mut nonce = [0; 12];
    nonce[11] = 1;
    let tag = aes.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&inout),
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

pub fn pre_reply(
    local_sk: &Key,
    mut enc_pub_key: SealedKey,
    ephemeral: Key,
    mut enc_ts: SealedTimestamp,
) -> Result<(Key, u64), Unspecified> {
    let local_sk = to_sk(local_sk);
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
        Aad::from(&enc_pub_key),
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
    pub(crate) eph: Key,
    pub(crate) sender_idx: u32,
    pub(crate) receiver_idx: u32,
}

pub fn post_reply(
    remote_pk: &Key,
    pre_shared_key: Option<&Key>,
    sender_idx: u32,
    receiver_idx: u32,
) -> Result<(Replying, Cipher), Unspecified> {
    let remote_pk = to_pk(remote_pk);

    let esk = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())?;
    let epk = esk.compute_public_key()?;
    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree_ephemeral(esk, remote_pk, Unspecified, |km| Ok(salt.extract(km)))?;

    let psk = pre_shared_key.map(|x| &x[..]).unwrap_or(b"");
    let info = [psk, b"for-session"];
    let okm = prk.expand(&info, &aead::CHACHA20_POLY1305)?;
    let key = LessSafeKey::new(aead::UnboundKey::from(okm));

    Ok((
        Replying {
            eph: pk_to_bytes(&epk),
            sender_idx,
            receiver_idx,
        },
        Cipher::new(key, false),
    ))
}

pub fn finish(
    local_sk: &Key,
    pre_shared_key: Option<&Key>,
    eph: Key,
) -> Result<Cipher, Unspecified> {
    let local_sk = to_sk(local_sk);
    let remote_epk = UnparsedPublicKey::new(&X25519, &eph);

    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree(
        &local_sk,
        remote_epk,
        Unspecified,
        |km| Ok(salt.extract(km)),
    )?;
    let psk = pre_shared_key.map(|x| &x[..]).unwrap_or(b"");
    let info = [psk, b"for-session"];
    let okm = prk.expand(&info, &aead::CHACHA20_POLY1305)?;
    let key = LessSafeKey::new(aead::UnboundKey::from(okm));

    Ok(Cipher::new(key, true))
}

pub struct Cipher {
    enc_dec: [AtomicU64; 2],
    key: LessSafeKey,
    is_initiator: bool,
}

impl Cipher {
    /// Peers sharing a key must use opposite roles to avoid nonce reuse.
    pub fn new(key: LessSafeKey, is_initiator: bool) -> Self {
        Self {
            enc_dec: [const { AtomicU64::new(1) }; 2],
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
        let value = self.enc_dec[0]
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
        let next = nonce.checked_add(1).ok_or(Unspecified)?;
        if nonce < self.enc_dec[1].load(Ordering::Relaxed) {
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
        // Update only after authentication; concurrent duplicates cannot both succeed.
        self.enc_dec[1]
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |expected| {
                (nonce >= expected).then_some(next)
            })
            .map_err(|_| Unspecified)?;
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_reply() {
        let sk1 = PrivateKey::generate(&X25519).unwrap();
        let sk2 = PrivateKey::generate(&X25519).unwrap();

        let i = initiate(
            &sk_to_bytes(&sk1),
            &pk_to_bytes(&sk2.compute_public_key().unwrap()),
            u64::MAX,
            0,
        )
        .unwrap();

        let (pk, timestamp) =
            pre_reply(&sk_to_bytes(&sk2), i.enc_pub_key, i.ephemeral, i.enc_ts).unwrap();
        assert_eq!(timestamp, u64::MAX);
        assert_eq!(pk.as_ref(), pk_to_bytes(&sk1.compute_public_key().unwrap()));
    }

    #[test]
    fn test_finish() {
        for psk in [None, Some([7; 32])] {
            let initiator = PrivateKey::generate(&X25519).unwrap();
            let responder = PrivateKey::generate(&X25519).unwrap();
            let local_sk = sk_to_bytes(&initiator);
            let initiation = initiate(
                &local_sk,
                &pk_to_bytes(&responder.compute_public_key().unwrap()),
                u64::MAX,
                0,
            )
            .unwrap();
            let (remote_pk, timestamp) = pre_reply(
                &sk_to_bytes(&responder),
                initiation.enc_pub_key,
                initiation.ephemeral,
                initiation.enc_ts,
            )
            .unwrap();
            let (reply, responder_key) =
                post_reply(&remote_pk.as_ref().try_into().unwrap(), psk.as_ref(), 0, 0).unwrap();
            let initiator_key = finish(&local_sk, psk.as_ref(), reply.eph).unwrap();
            assert_eq!(timestamp, u64::MAX);

            let (nonce, message) = responder_key.encrypt(b"session message".to_vec()).unwrap();
            let replay = message.clone();
            assert_eq!(
                initiator_key.decrypt(nonce, message).unwrap(),
                b"session message"
            );
            assert!(initiator_key.decrypt(nonce, replay).is_err());

            let (nonce, message) = initiator_key.encrypt(b"return message".to_vec()).unwrap();
            assert_eq!(
                responder_key.decrypt(nonce, message).unwrap(),
                b"return message"
            );

            let (nonce, message) = responder_key.encrypt(b"authenticated".to_vec()).unwrap();
            let mut tampered = message.clone();
            tampered[0] ^= 1;
            assert!(initiator_key.decrypt(nonce + 100, tampered).is_err());
            assert_eq!(
                initiator_key.decrypt(nonce, message).unwrap(),
                b"authenticated"
            );

            responder_key.enc_dec[0].store(u64::MAX, Ordering::Relaxed);
            assert!(responder_key.encrypt(vec![]).is_err());
            assert!(responder_key.encrypt(vec![]).is_err());
        }
    }

    #[test]
    fn test_initiation_rejects_tampering() {
        let initiator = random_sk().unwrap();
        let responder = random_sk().unwrap();
        for tamper_timestamp in [false, true] {
            let mut initiation = initiate(
                &sk_to_bytes(&initiator),
                &pk_to_bytes(&responder.compute_public_key().unwrap()),
                123,
                0,
            )
            .unwrap();
            if tamper_timestamp {
                initiation.enc_ts[0] ^= 1;
            } else {
                initiation.enc_pub_key[0] ^= 1;
            }
            assert!(
                pre_reply(
                    &sk_to_bytes(&responder),
                    initiation.enc_pub_key,
                    initiation.ephemeral,
                    initiation.enc_ts
                )
                .is_err()
            );
        }
    }

    #[test]
    fn test_wrong_psk_rejects_session_data() {
        let initiator = random_sk().unwrap();
        let (reply, responder) = post_reply(
            &pk_to_bytes(&initiator.compute_public_key().unwrap()),
            Some(&[7; 32]),
            0,
            0,
        )
        .unwrap();
        let initiator = finish(&sk_to_bytes(&initiator), Some(&[8; 32]), reply.eph).unwrap();
        let (counter, data) = responder.encrypt(b"message".to_vec()).unwrap();
        assert!(initiator.decrypt(counter, data).is_err());
    }
}
