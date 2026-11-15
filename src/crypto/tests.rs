use super::*;

fn cipher_pair() -> (Cipher, Cipher) {
    let make = |initiator| {
        Cipher::new(
            LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &[7; 32]).unwrap()),
            initiator,
        )
    };
    (make(true), make(false))
}

#[test]
fn nonce_lag_accepts_reordering_and_repeated_packets() {
    let (sender, receiver) = cipher_pair();
    let mut packets: Vec<_> = (0..202)
        .map(|_| sender.encrypt(b"reordered".to_vec()).unwrap())
        .collect();
    let (newest, ciphertext) = packets.pop().unwrap();
    assert_eq!(newest, 202);
    assert_eq!(receiver.decrypt(newest, ciphertext).unwrap(), b"reordered");

    // Highest 202 admits nonces 2..=202; nonce 1 is more than 200 behind.
    let (oldest, oldest_ciphertext) = packets.remove(0);
    assert_eq!(oldest, 1);
    for (nonce, ciphertext) in packets.into_iter().rev() {
        let duplicate = ciphertext.clone();
        assert_eq!(receiver.decrypt(nonce, ciphertext).unwrap(), b"reordered");
        assert_eq!(receiver.decrypt(nonce, duplicate).unwrap(), b"reordered");
    }
    assert_eq!(receiver.decrypt_counter.load(Ordering::Relaxed), 202);
    assert!(receiver.decrypt(oldest, oldest_ciphertext).is_err());
}

#[test]
fn unauthenticated_future_nonce_does_not_advance_highest_nonce() {
    let (sender, receiver) = cipher_pair();
    let (nonce, ciphertext) = sender.encrypt(b"still valid".to_vec()).unwrap();
    sender.encrypt_counter.store(10_000, Ordering::Relaxed);
    let (future_nonce, future_ciphertext) = sender.encrypt(b"future".to_vec()).unwrap();
    let mut tampered = future_ciphertext.clone();
    tampered[0] ^= 1;
    assert!(receiver.decrypt(future_nonce, tampered).is_err());
    assert_eq!(receiver.decrypt(nonce, ciphertext).unwrap(), b"still valid");
    assert_eq!(
        receiver.decrypt(future_nonce, future_ciphertext).unwrap(),
        b"future"
    );
    let (zero_nonce_sender, receiver) = cipher_pair();
    zero_nonce_sender
        .encrypt_counter
        .store(0, Ordering::Relaxed);
    let (nonce, ciphertext) = zero_nonce_sender.encrypt(vec![]).unwrap();
    assert!(receiver.decrypt(nonce, ciphertext).is_err());
}

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

    let (pk, timestamp) = pre_reply(&sk_to_bytes(&sk2), &i).unwrap();
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
        let (remote_pk, timestamp) = pre_reply(&sk_to_bytes(&responder), &initiation).unwrap();
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
        assert_eq!(
            initiator_key.decrypt(nonce, replay).unwrap(),
            b"session message"
        );

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

        responder_key
            .encrypt_counter
            .store(u64::MAX, Ordering::Relaxed);
        assert!(responder_key.encrypt(vec![]).is_err());
        assert!(responder_key.encrypt(vec![]).is_err());
    }
}

#[test]
fn test_initiation_rejects_tampering() {
    let initiator = random_sk().unwrap();
    let responder = random_sk().unwrap();
    let initiation = initiate(
        &sk_to_bytes(&initiator),
        &pk_to_bytes(&responder.compute_public_key().unwrap()),
        123,
        0x12345678,
    )
    .unwrap();
    // Every byte of every field must be authenticated, including sender index
    // (previously mutable without invalidating the timestamp tag).
    for field in 0..4 {
        let len = [32, 48, 24, 4][field];
        for byte in 0..len {
            let mut tampered = initiation.clone();
            match field {
                0 => tampered.ephemeral[byte] ^= 1,
                1 => tampered.enc_pub_key[byte] ^= 1,
                2 => tampered.enc_ts[byte] ^= 1,
                3 => tampered.sender_idx ^= 1 << (byte * 8),
                _ => unreachable!(),
            }
            assert!(
                pre_reply(&sk_to_bytes(&responder), &tampered).is_err(),
                "accepted tampered field {field}, byte {byte}"
            );
        }
    }
    assert!(pre_reply(&sk_to_bytes(&responder), &initiation).is_ok());
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

#[test]
fn shared_cipher_uses_unique_nonces_and_accepts_reordered_packets() {
    use std::sync::{Arc, Barrier};

    let initiator = random_sk().unwrap();
    let (reply, responder) = post_reply(
        &pk_to_bytes(&initiator.compute_public_key().unwrap()),
        None,
        0,
        0,
    )
    .unwrap();
    let sender = Arc::new(finish(&sk_to_bytes(&initiator), None, reply.eph).unwrap());
    let receiver = Arc::new(responder);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let sender = sender.clone();
            std::thread::spawn(move || {
                (0..50)
                    .map(|_| sender.encrypt(b"shared cipher".to_vec()).unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut encrypted: Vec<_> = threads
        .into_iter()
        .flat_map(|thread| thread.join().unwrap())
        .collect();
    // Check nonce uniqueness, then decrypt a whole window concurrently out of order.
    encrypted.sort_unstable_by_key(|(nonce, _)| *nonce);
    for (index, (nonce, _)) in encrypted.iter().enumerate() {
        assert_eq!(*nonce, index as u64 + 1);
    }
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = encrypted
        .chunks(50)
        .map(|chunk| {
            let packets = chunk.to_vec();
            let receiver = receiver.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for (nonce, ciphertext) in packets.into_iter().rev() {
                    assert_eq!(
                        receiver.decrypt(nonce, ciphertext).unwrap(),
                        b"shared cipher"
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }

    let (nonce, ciphertext) = sender.encrypt(b"concurrent replay".to_vec()).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let receiver = receiver.clone();
            let ciphertext = ciphertext.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                receiver.decrypt(nonce, ciphertext).is_ok()
            })
        })
        .collect();
    let accepted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 4);
}
