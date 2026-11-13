use crate::crypto::{Initiating, Replying};

use bytes::{Buf, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketLayout {
    #[serde(rename = "m")]
    pub mask: u32, // general field mask
    pub o_ty: usize,    // offset of packet ty
    pub oi_eph: usize,  // (initiating) offset of ephemeral key
    pub oi_epk: usize,  // (initiating) offset of encrypted public key
    pub or_eph: usize,  // (replying) offset of ephemeral key
    pub or_ets: usize,  // (replying) offset of encrypted timestamp
    pub oi_sidx: usize, // (initiating) offset of sender index
    pub or_sidx: usize, // (replying) offset of sender index
    pub or_ridx: usize, // (replying) offset of receiver index
    pub od_non: usize,  // (data) offset of nonce
    pub od_dl: usize,   // (data) offset of data length
    pub od_d: usize,    // (data) offset of data itself
}

impl PacketLayout {
    pub fn check(&self) -> Result<(), &'static str> {
        let r = |x: usize, o: usize| x..x + o;
        #[rustfmt::skip]
        let ranges = [
            r(self.oi_eph, 32),
            r(self.oi_epk, 48),
            r(self.oi_sidx, 4),
            r(self.or_eph, 32),
            r(self.or_ets, 24),
            r(self.or_sidx, 4),
            r(self.or_ridx, 4),
            r(self.od_non, 12),
            r(self.od_dl, 4),
        ];

        // Data has a variable length, so reserve everything from od_d onward.
        if self.o_ty >= self.od_d
            || ranges[7..9]
                .iter()
                .any(|range| range.start < range.end && range.end > self.od_d)
        {
            return Err("data overlaps packet fields");
        }

        let ty_range = self.o_ty
            ..self
                .o_ty
                .checked_add(1)
                .ok_or("packet type offset overflows")?;
        for group in [0..3, 3..7, 7..9] {
            for (i, r1) in ranges[group.clone()]
                .iter()
                .chain(std::iter::once(&ty_range))
                .enumerate()
            {
                for (j, r2) in ranges[group.clone()]
                    .iter()
                    .chain(std::iter::once(&ty_range))
                    .enumerate()
                {
                    let overlaps = (r1.start < r2.end) & (r2.start < r1.end);
                    if i != j && overlaps {
                        return Err("packet ranges overlap");
                    }
                }
            }
        }

        Ok(())
    }
}

impl PacketLayout {
    fn ilen(&self) -> usize {
        [self.oi_eph + 32, self.oi_epk + 48, self.oi_sidx + 4]
            .into_iter()
            .max()
            .unwrap()
    }

    fn rlen(&self) -> usize {
        [
            self.or_eph + 32,
            self.or_ets + 24,
            self.or_sidx + 4,
            self.or_ridx + 4,
        ]
        .into_iter()
        .max()
        .unwrap()
    }
}

impl Default for PacketLayout {
    fn default() -> Self {
        Self {
            mask: 0,
            o_ty: 0,
            oi_eph: 1,
            oi_epk: 1 + 32,
            or_eph: 1,
            or_ets: 1 + 32,
            oi_sidx: 81,
            or_sidx: 57,
            or_ridx: 61,
            od_non: 1,
            od_dl: 1 + 12,
            od_d: 1 + 12 + 4,
        }
    }
}

#[derive(Debug)]
pub enum Packet {
    Initiating(Initiating),
    Reply(Replying),
    Data { nonce: [u8; 12], data: Bytes },
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Received unexpected packet type {0}")]
    UnexpectedTy(u8),
    #[error("Tried encoding a packet that is too large")]
    PacketOverflow,
    #[error("Io: {0}")]
    Io(#[from] io::Error),
}

/// Consumes one complete packet, leaving incomplete or invalid input untouched.
pub fn parse(buf: &mut BytesMut, layout: &PacketLayout) -> Option<Result<Packet, Error>> {
    if buf.len() < layout.o_ty + 1 {
        return None;
    }

    let ty = buf[layout.o_ty] ^ layout.mask as u8;
    match ty {
        // initiating
        0 => {
            let ephemeral = get_masked_at(buf, layout.oi_eph, layout.mask)?;
            let enc_pub_key = get_masked_at(buf, layout.oi_epk, layout.mask)?;

            let sender_idx = u32::from_be_bytes(get_masked_at(buf, layout.oi_sidx, layout.mask)?);
            let packet = Packet::Initiating(Initiating {
                sender_idx,
                enc_pub_key,
                ephemeral,
            });
            let consumed = layout.ilen().max(layout.o_ty + 1);
            buf.advance(consumed);
            return Some(Ok(packet));
        }
        // reply
        1 => {
            let ephemeral = get_masked_at(buf, layout.or_eph, layout.mask)?;
            let enc_ts = get_masked_at(buf, layout.or_ets, layout.mask)?;

            let sender_idx = u32::from_be_bytes(get_masked_at(buf, layout.or_sidx, layout.mask)?);
            let receiver_idx = u32::from_be_bytes(get_masked_at(buf, layout.or_ridx, layout.mask)?);
            let packet = Packet::Reply(Replying {
                sender_idx,
                receiver_idx,
                eph: ephemeral,
                enc_ts,
            });
            let consumed = layout.rlen().max(layout.o_ty + 1);
            buf.advance(consumed);
            return Some(Ok(packet));
        }
        // data
        2 => {
            let nonce = get_masked_at(buf, layout.od_non, layout.mask)?;
            let len = u32::from_be_bytes(get_masked_at(buf, layout.od_dl, layout.mask)?);
            let end = layout.od_d.checked_add(usize::try_from(len).ok()?)?;
            let consumed = end
                .max(layout.od_non.checked_add(12)?)
                .max(layout.od_dl.checked_add(4)?)
                .max(layout.o_ty.checked_add(1)?);
            if buf.len() < consumed {
                return None;
            }
            let data = buf.split_to(consumed).freeze().slice(layout.od_d..end);

            return Some(Ok(Packet::Data { nonce, data }));
        }
        _ => return Some(Err(Error::UnexpectedTy(ty))),
    }
}

/// Appends a packet using layout-relative offsets, randomizing unused bytes.
/// The layout must have passed `PacketLayout::check`.
pub fn append(buf: &mut BytesMut, packet: Packet, layout: &PacketLayout) -> Result<(), Error> {
    let ty_end = layout.o_ty.checked_add(1).ok_or(Error::PacketOverflow)?;
    let (ty, len) = match &packet {
        Packet::Initiating(_) => (0, layout.ilen().max(ty_end)),
        Packet::Reply(_) => (1, layout.rlen().max(ty_end)),
        Packet::Data { data, .. } => {
            u32::try_from(data.len()).map_err(|_| Error::PacketOverflow)?;
            let len = layout
                .od_d
                .checked_add(data.len())
                .ok_or(Error::PacketOverflow)?
                .max(layout.od_non.checked_add(12).ok_or(Error::PacketOverflow)?)
                .max(layout.od_dl.checked_add(4).ok_or(Error::PacketOverflow)?)
                .max(ty_end);
            (2, len)
        }
    };
    let start = buf.len();
    let end = start.checked_add(len).ok_or(Error::PacketOverflow)?;
    buf.resize(end, 0);
    fastrand::fill(&mut buf[start..end]);
    let out = &mut buf[start..end];
    out[layout.o_ty] = ty ^ layout.mask as u8;
    match packet {
        Packet::Initiating(Initiating {
            enc_pub_key,
            ephemeral,
            sender_idx,
        }) => {
            put_masked_at(out, layout.oi_sidx, &sender_idx.to_be_bytes(), layout.mask);
            put_masked_at(out, layout.oi_eph, &ephemeral, layout.mask);
            put_masked_at(out, layout.oi_epk, &enc_pub_key, layout.mask);
        }
        Packet::Reply(Replying {
            enc_ts,
            eph,
            sender_idx,
            receiver_idx,
        }) => {
            put_masked_at(out, layout.or_sidx, &sender_idx.to_be_bytes(), layout.mask);
            put_masked_at(
                out,
                layout.or_ridx,
                &receiver_idx.to_be_bytes(),
                layout.mask,
            );
            put_masked_at(out, layout.or_eph, &eph, layout.mask);
            put_masked_at(out, layout.or_ets, &enc_ts, layout.mask);
        }
        Packet::Data { nonce, data } => {
            put_masked_at(out, layout.od_non, &nonce, layout.mask);
            put_masked_at(
                out,
                layout.od_dl,
                &(data.len() as u32).to_be_bytes(),
                layout.mask,
            );
            out[layout.od_d..layout.od_d + data.len()].copy_from_slice(&data);
        }
    }
    Ok(())
}

fn put_masked_at(buf: &mut [u8], pos: usize, value: &[u8], mask: u32) {
    for ((dst, src), mask) in buf[pos..pos + value.len()]
        .iter_mut()
        .zip(value)
        .zip(mask.to_be_bytes().iter().cycle())
    {
        *dst = *src ^ *mask;
    }
}

fn get_masked_at<const N: usize>(buf: &[u8], pos: usize, mask: u32) -> Option<[u8; N]> {
    let mut k: [u8; N] = buf.get(pos..)?.get(..N)?.try_into().ok()?;
    for (b, m) in k.iter_mut().zip(mask.to_be_bytes().iter().cycle()) {
        *b ^= *m;
    }

    Some(k)
}

pub struct Codec {
    layout: PacketLayout,
}

impl Codec {
    pub fn new(layout: PacketLayout) -> Self {
        Self { layout }
    }
}

impl Decoder for Codec {
    type Item = Packet;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        parse(src, &self.layout).transpose()
    }
}

impl Encoder<Packet> for Codec {
    type Error = Error;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        append(dst, item, &self.layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_layout_wf() {
        let pl = PacketLayout::default();
        assert!(pl.check().is_ok());
    }

    #[test]
    fn test_parse_handshake_packets() {
        let layout = PacketLayout::default();
        let mut initiation = vec![0; layout.ilen()];
        initiation[layout.oi_eph..layout.oi_eph + 32].fill(7);
        initiation[layout.oi_epk..layout.oi_epk + 48].fill(8);
        let mut buf = BytesMut::from(initiation.as_slice());
        let Packet::Initiating(packet) = parse(&mut buf, &layout).unwrap().unwrap() else {
            panic!("expected initiation");
        };
        assert_eq!(packet.ephemeral, [7; 32]);
        assert_eq!(packet.enc_pub_key, [8; 48]);
        assert!(buf.is_empty());
        let mut partial = BytesMut::from(&initiation[..84]);
        let original = partial.clone();
        assert!(parse(&mut partial, &layout).is_none());
        assert_eq!(partial, original);

        let mut reply = vec![0; layout.rlen()];
        reply[layout.o_ty] = 1;
        reply[layout.or_eph..layout.or_eph + 32].fill(9);
        reply[layout.or_ets..layout.or_ets + 24].fill(10);
        let mut buf = BytesMut::from(reply.as_slice());
        let Packet::Reply(packet) = parse(&mut buf, &layout).unwrap().unwrap() else {
            panic!("expected reply");
        };
        assert_eq!(packet.eph, [9; 32]);
        assert_eq!(packet.enc_ts, [10; 24]);
        assert!(buf.is_empty());
        let mut partial = BytesMut::from(&reply[..64]);
        let original = partial.clone();
        assert!(parse(&mut partial, &layout).is_none());
        assert_eq!(partial, original);
    }

    #[test]
    fn test_type_layout_overlap() {
        // Check both ends of every fixed field in all packet variants.
        for o_ty in [1, 32, 33, 80, 56, 12, 13, 16] {
            let layout = PacketLayout {
                o_ty,
                od_d: 100,
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err(), "type offset {o_ty}");
        }
    }

    #[test]
    fn test_index_layout_overlap() {
        for layout in [
            PacketLayout {
                oi_sidx: 0,
                ..PacketLayout::default()
            },
            PacketLayout {
                oi_sidx: 78,
                ..PacketLayout::default()
            },
            PacketLayout {
                or_sidx: 31,
                ..PacketLayout::default()
            },
            PacketLayout {
                or_ridx: 55,
                ..PacketLayout::default()
            },
            PacketLayout {
                or_ridx: 60,
                ..PacketLayout::default()
            },
        ] {
            assert!(layout.check().is_err());
        }
    }

    #[test]
    fn test_data_layout_overlap() {
        for od_d in [0, 1, 12, 13, 16] {
            let layout = PacketLayout {
                od_d,
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err());
        }
        let layout = PacketLayout {
            o_ty: 17,
            ..PacketLayout::default()
        };
        assert!(layout.check().is_err());
    }

    #[test]
    fn test_parse_data() {
        for mask in [0u32, 0x12345678] {
            let layout = PacketLayout {
                mask,
                ..PacketLayout::default()
            };
            for payload in [&b"hello"[..], &b""[..]] {
                let mut packet = vec![0; layout.od_d];
                packet[layout.o_ty] = 2 ^ mask as u8;
                for (i, byte) in [7u8; 12].into_iter().enumerate() {
                    packet[layout.od_non + i] = byte ^ mask.to_be_bytes()[i % 4];
                }
                for (i, byte) in (payload.len() as u32).to_be_bytes().into_iter().enumerate() {
                    packet[layout.od_dl + i] = byte ^ mask.to_be_bytes()[i % 4];
                }
                packet.extend_from_slice(payload);
                let packet = Bytes::from(packet);
                let expected_len = packet.len();
                for len in 0..expected_len {
                    let mut partial = BytesMut::from(&packet[..len]);
                    let original = partial.clone();
                    assert!(parse(&mut partial, &layout).is_none());
                    assert_eq!(partial, original);
                }
                let mut with_trailing = packet.to_vec();
                with_trailing.extend_from_slice(b"trailing");
                let mut buf = BytesMut::from(with_trailing.as_slice());
                let payload_ptr = buf[layout.od_d..].as_ptr();
                let Packet::Data { nonce, data } = parse(&mut buf, &layout).unwrap().unwrap()
                else {
                    panic!("expected data");
                };
                assert_eq!(nonce, [7; 12]);
                assert_eq!(data, payload);
                assert_eq!(&buf[..], b"trailing");
                assert_eq!(data.as_ptr(), payload_ptr);
            }
        }
    }

    #[test]
    fn test_decode_concatenated_packets() {
        let mut codec = Codec {
            layout: PacketLayout::default(),
        };
        let mut src = BytesMut::from(&[0u8; 85][..]);
        let mut reply = vec![0; 65];
        reply[0] = 1;
        src.extend_from_slice(&reply[..64]);
        assert!(matches!(
            codec.decode(&mut src).unwrap(),
            Some(Packet::Initiating(_))
        ));
        let partial = src.clone();
        assert!(codec.decode(&mut src).unwrap().is_none());
        assert_eq!(src, partial);
        src.extend_from_slice(&reply[64..]);
        assert!(matches!(
            codec.decode(&mut src).unwrap(),
            Some(Packet::Reply(_))
        ));
        assert!(src.is_empty());

        src.extend_from_slice(&[3]);
        assert!(matches!(
            codec.decode(&mut src),
            Err(Error::UnexpectedTy(3))
        ));
        assert_eq!(&src[..], &[3]);
    }

    #[test]
    fn test_encode_round_trip() {
        for mask in [0, 0x12345678] {
            let mut codec = Codec {
                layout: PacketLayout {
                    mask,
                    o_ty: 2,
                    oi_eph: 5,
                    oi_epk: 40,
                    or_eph: 6,
                    or_ets: 40,
                    oi_sidx: 90,
                    or_sidx: 70,
                    or_ridx: 80,
                    od_non: 5,
                    od_dl: 20,
                    od_d: 28,
                },
            };
            codec.layout.check().unwrap();
            let mut buf = BytesMut::from(&b"prefix"[..]);
            codec
                .encode(
                    Packet::Initiating(Initiating {
                        sender_idx: 0x12345678,
                        enc_pub_key: [8; 48],
                        ephemeral: [7; 32],
                    }),
                    &mut buf,
                )
                .unwrap();
            codec
                .encode(
                    Packet::Reply(Replying {
                        sender_idx: 0x87654321,
                        receiver_idx: 0x12345678,
                        enc_ts: [10; 24],
                        eph: [9; 32],
                    }),
                    &mut buf,
                )
                .unwrap();
            for data in [Bytes::from_static(b"payload"), Bytes::new()] {
                codec
                    .encode(
                        Packet::Data {
                            nonce: [11; 12],
                            data,
                        },
                        &mut buf,
                    )
                    .unwrap();
            }
            assert_eq!(&buf.split_to(6)[..], b"prefix");
            let Some(Packet::Initiating(packet)) = codec.decode(&mut buf).unwrap() else {
                panic!("expected initiation")
            };
            assert_eq!(packet.sender_idx, 0x12345678);
            assert_eq!(packet.enc_pub_key, [8; 48]);
            assert_eq!(packet.ephemeral, [7; 32]);
            let Some(Packet::Reply(packet)) = codec.decode(&mut buf).unwrap() else {
                panic!("expected reply")
            };
            assert_eq!(packet.sender_idx, 0x87654321);
            assert_eq!(packet.receiver_idx, 0x12345678);
            assert_eq!(packet.enc_ts, [10; 24]);
            assert_eq!(packet.eph, [9; 32]);
            for expected in [&b"payload"[..], &b""[..]] {
                let Some(Packet::Data { nonce, data }) = codec.decode(&mut buf).unwrap() else {
                    panic!("expected data")
                };
                assert_eq!(nonce, [11; 12]);
                assert_eq!(data, expected);
            }
            assert!(buf.is_empty());
        }
    }
}
