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

#[derive(Debug)]
pub struct Initiating {
    enc_pub_key: SealedKey,
    ephemeral: Key,
}

pub fn initiate(local_sk: &Key, remote_pk: &Key) -> Result<Initiating, Unspecified> {
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

    Ok(Initiating {
        enc_pub_key: inout.try_into().unwrap(),
        ephemeral: pk_to_bytes(&epk),
    })
}

pub fn pre_reply(
    local_sk: &Key,
    Initiating {
        mut enc_pub_key,
        ephemeral,
    }: Initiating,
) -> Result<ParsedPublicKey, Unspecified> {
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

    let pub_key = &*cipher.open_within(
        Nonce::assume_unique_for_key([0; _]),
        Aad::empty(),
        &mut enc_pub_key,
        0..,
    )?;

    Ok(UnparsedPublicKey::new(&X25519, pub_key).try_into().unwrap())
}

#[derive(Debug)]
pub struct Replying {
    enc_ts: SealedTimestamp,
    eph: Key,
}

pub fn post_reply(
    remote_pk: &Key,
    pre_shared_key: Option<&Key>,
    timestamp: i64,
) -> Result<(Replying, LessSafeKey), Unspecified> {
    let remote_pk = to_pk(remote_pk);

    let esk = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())?;
    let epk = esk.compute_public_key()?;
    let salt = hkdf::Salt::none(HKDF_SHA256);
    let prk = ka::agree_ephemeral(esk, remote_pk, Unspecified, |km| Ok(salt.extract(km)))?;

    let psk = pre_shared_key.map(|x| &x[..]).unwrap_or(b"");
    let info = [psk, b"for-session"];
    let okm = prk.expand(&info, &aead::CHACHA20_POLY1305)?;
    let cipher = LessSafeKey::new(aead::UnboundKey::from(okm));

    let mut in_out = [0; 24];
    in_out[..8].copy_from_slice(&timestamp.to_be_bytes());
    let tag = cipher.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key([0; _]),
        Aad::empty(),
        &mut in_out[..8],
    )?;
    in_out[8..].copy_from_slice(tag.as_ref());

    Ok((
        Replying {
            eph: pk_to_bytes(&epk),
            enc_ts: in_out,
        },
        cipher,
    ))
}

pub fn finish(
    local_sk: &Key,
    pre_shared_key: Option<&Key>,
    Replying { mut enc_ts, eph }: Replying,
) -> Result<(i64, LessSafeKey), Unspecified> {
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
    let cipher = LessSafeKey::new(aead::UnboundKey::from(okm));

    let timestamp = cipher.open_in_place(
        Nonce::assume_unique_for_key([0; _]),
        Aad::empty(),
        &mut enc_ts,
    )?;
    let timestamp = i64::from_be_bytes(timestamp.try_into().map_err(|_| Unspecified)?);

    Ok((timestamp, cipher))
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
        )
        .unwrap();

        let pk = pre_reply(&sk_to_bytes(&sk2), i).unwrap();
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
            )
            .unwrap();
            let remote_pk = pre_reply(&sk_to_bytes(&responder), initiation).unwrap();
            let (reply, responder_key) =
                post_reply(&remote_pk.as_ref().try_into().unwrap(), psk.as_ref(), -123).unwrap();
            let (timestamp, initiator_key) = finish(&local_sk, psk.as_ref(), reply).unwrap();
            assert_eq!(timestamp, -123);

            let mut message = b"session message".to_vec();
            let mut nonce = [0; 12];
            nonce[11] = 1;
            responder_key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut message,
                )
                .unwrap();
            let plaintext = initiator_key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut message,
                )
                .unwrap();
            assert_eq!(plaintext, b"session message");
        }
    }

    #[test]
    fn test_finish_rejects_wrong_psk_and_tampering() {
        let initiator = PrivateKey::generate(&X25519).unwrap();
        let local_sk = sk_to_bytes(&initiator);
        let remote_pk = pk_to_bytes(&initiator.compute_public_key().unwrap());
        let (reply, _) = post_reply(&remote_pk, Some(&[7; 32]), 123).unwrap();
        assert!(finish(&local_sk, Some(&[8; 32]), reply).is_err());

        let (mut reply, _) = post_reply(&remote_pk, None, 123).unwrap();
        reply.enc_ts[0] ^= 1;
        assert!(finish(&local_sk, None, reply).is_err());
    }
}
