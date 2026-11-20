//! QUIC v1-shaped UDP framing for Covert packets.
use crate::{
    Error, Result,
    codec::{self, Packet, PacketLayout},
};
use aws_lc_rs::{aead, digest};
use bytes::Bytes;
use std::sync::OnceLock;

const CID_LEN: usize = 8;
const VERSION: [u8; 4] = 1u32.to_be_bytes();
const INITIAL_MIN: usize = 1200;
const LONG_PREFIX: usize = 2 * CID_LEN + 8;
const MIN_LONG_HEADER: usize = LONG_PREFIX + 2;
const SHORT_HEADER: usize = 1 + CID_LEN;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_UDP_PAYLOAD: usize = 65507;
pub(crate) const DATA_OVERHEAD: usize = SHORT_HEADER + NONCE_LEN + TAG_LEN;

fn cid(label: u8, index: u32) -> [u8; CID_LEN] {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"covert-quic-cid-v1");
    hash.update(&[label]);
    hash.update(&index.to_be_bytes());
    hash.finish().as_ref()[..CID_LEN].try_into().unwrap()
}

fn connection_ids(packet: &Packet) -> ([u8; CID_LEN], Option<[u8; CID_LEN]>) {
    match packet {
        Packet::Initiating(p) => (cid(0, p.sender_idx), Some(cid(1, p.sender_idx))),
        Packet::Reply(p) => (cid(1, p.receiver_idx), Some(cid(1, p.sender_idx))),
        Packet::Data(p) => (cid(1, p.receiver_idx), None),
    }
}

fn framing_key() -> &'static aead::LessSafeKey {
    // Public wire-format constant. The inner tunnel provides security.
    static KEY: OnceLock<aead::LessSafeKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = aead::UnboundKey::new(&aead::AES_128_GCM, b"Covert QUIC v1  ").unwrap();
        aead::LessSafeKey::new(key)
    })
}

pub(super) fn encode(packet: Packet, layout: &PacketLayout) -> Result<Bytes> {
    let (dest, source) = connection_ids(&packet);
    let payload = packet.to_bytes(layout)?;
    let body_len = NONCE_LEN + payload.len() + TAG_LEN;
    let length_width = if body_len < 1 << 14 { 2 } else { 4 };
    let long_header = LONG_PREFIX + length_width;
    let total = match source {
        Some(_) => INITIAL_MIN.max(long_header + body_len),
        None => SHORT_HEADER + body_len,
    };
    if total > MAX_UDP_PAYLOAD {
        return Err(Error::PacketOverflow);
    }

    let mut wire = Vec::with_capacity(total);
    if let Some(source) = source {
        wire.push(0xc0 | fastrand::u8(0..16));
        wire.extend(VERSION);
        wire.push(CID_LEN as u8);
        wire.extend(dest);
        wire.push(CID_LEN as u8);
        wire.extend(source);
        wire.push(0); // Empty Initial token.
        let length = (total - long_header) as u32;
        if length_width == 2 {
            wire.extend((0x4000 | length as u16).to_be_bytes());
        } else {
            wire.extend((0x8000_0000 | length).to_be_bytes());
        }
    } else {
        wire.push(0x40 | fastrand::u8(0..32));
        wire.extend(dest);
    }
    let mut nonce = [0; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce)?;
    // The nonce starts at the apparent packet number and continues in the body.
    wire.extend(nonce);
    let start = wire.len();
    wire.extend_from_slice(&payload);
    wire.resize(total - TAG_LEN, 0);
    let (header, body) = wire.split_at_mut(start);
    let tag = framing_key().seal_in_place_separate_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(header),
        body,
    )?;
    wire.extend_from_slice(tag.as_ref());
    Ok(wire.into())
}

pub(super) fn decode(wire: &[u8], layout: &PacketLayout) -> Result<Packet> {
    let malformed = Error::MalformedDatagram;
    let first = *wire.first().ok_or(Error::MalformedDatagram)?;
    let long = match first {
        0xc0..=0xcf => true,
        0x40..=0x5f => false,
        _ => return Err(malformed),
    };
    if wire.len() > MAX_UDP_PAYLOAD {
        return Err(malformed);
    }
    let header_len = if long {
        initial_header_len(wire).ok_or(Error::MalformedDatagram)?
    } else {
        SHORT_HEADER
    };
    let start = header_len + NONCE_LEN;
    if wire.len() <= start + TAG_LEN {
        return Err(malformed);
    }

    let nonce = wire[header_len..start].try_into().unwrap();
    let mut body = wire[start..].to_vec();
    let payload = framing_key()
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&wire[..start]),
            &mut body,
        )
        .map_err(|_| Error::MalformedDatagram)?;
    let Some(Ok((packet, consumed))) = codec::parse_slice(payload, layout) else {
        return Err(malformed);
    };
    let (dest, source) = connection_ids(&packet);
    match (long, source) {
        (true, Some(source))
            if wire[6..6 + CID_LEN] == dest
                && wire[7 + CID_LEN..7 + 2 * CID_LEN] == source
                && wire.len() == INITIAL_MIN.max(start + consumed + TAG_LEN)
                && payload[consumed..].iter().all(|&byte| byte == 0) =>
        {
            Ok(packet)
        }
        (false, None) if wire[1..SHORT_HEADER] == dest && consumed == payload.len() => Ok(packet),
        _ => Err(malformed),
    }
}

fn initial_header_len(wire: &[u8]) -> Option<usize> {
    if wire.len() < INITIAL_MIN
        || wire[1..5] != VERSION
        || wire[5] != CID_LEN as u8
        || wire[6 + CID_LEN] != CID_LEN as u8
        || wire[LONG_PREFIX - 1] != 0
    {
        return None;
    }

    let (end, length) = match wire[LONG_PREFIX] >> 6 {
        1 => (
            MIN_LONG_HEADER,
            u16::from_be_bytes(wire[LONG_PREFIX..MIN_LONG_HEADER].try_into().ok()?) as usize
                & 0x3fff,
        ),
        2 => {
            let end = LONG_PREFIX + 4;
            let length =
                u32::from_be_bytes(wire[LONG_PREFIX..end].try_into().ok()?) as usize & 0x3fff_ffff;
            (end, length)
        }
        _ => return None,
    };
    (length == wire.len() - end).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Data;

    #[test]
    fn initial_has_version_and_length_and_rejects_changed_framing() {
        let layout = PacketLayout::default();
        let packet = crate::crypto::Initiating {
            sender_idx: 85,
            enc_ts: [0; 24],
            enc_pub_key: [0; 48],
            ephemeral: [0; 32],
        };
        let wire = encode(Packet::Initiating(packet.clone()), &layout).unwrap();
        assert_eq!(wire.len(), 1200);
        assert_eq!(wire[0] & 0xf0, 0xc0);
        assert_eq!(&wire[1..5], &[0, 0, 0, 1]);
        assert_eq!(wire[5], 8);
        assert_eq!(wire[14], 8);
        assert_eq!(wire[23], 0);
        assert_eq!(u16::from_be_bytes([wire[24], wire[25]]), 0x4000 | 1174);
        assert!(matches!(decode(&wire, &layout), Ok(Packet::Initiating(p)) if p == packet));

        let mut invalid = wire.to_vec();
        invalid[6] ^= 1;
        assert!(decode(&invalid, &layout).is_err());
        assert!(decode(&wire[..1199], &layout).is_err());
        invalid = wire.to_vec();
        invalid.push(0);
        assert!(decode(&invalid, &layout).is_err());

        let padded = PacketLayout {
            oip: 17000,
            ..layout
        };
        let wire = encode(Packet::Initiating(packet.clone()), &padded).unwrap();
        assert_eq!(wire[24] >> 6, 2);
        assert!(matches!(decode(&wire, &padded), Ok(Packet::Initiating(p)) if p == packet));
    }

    #[test]
    fn short_header_keeps_the_destination_id_without_exposing_inner_bytes() {
        let layout = PacketLayout::default();
        let data = || {
            Packet::Data(Data {
                receiver_idx: 85,
                counter: 4,
                ciphertext: vec![7; 16],
            })
        };
        let plain = data().to_bytes(&layout).unwrap();
        let first = encode(data(), &layout).unwrap();
        let second = encode(data(), &layout).unwrap();
        assert_eq!(first.len(), plain.len() + DATA_OVERHEAD);
        assert_eq!(first[0] & 0xe0, 0x40);
        assert_eq!(&first[1..9], &second[1..9]);
        assert_ne!(&first[9..], &second[9..]);
        assert!(decode(&plain, &layout).is_err());
        assert!(
            matches!(decode(&first, &layout), Ok(Packet::Data(p)) if p.counter == 4 && p.ciphertext == vec![7; 16])
        );
        assert!(decode(&first[..first.len() - 1], &layout).is_err());
    }
}
