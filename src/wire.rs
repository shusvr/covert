use std::io;

use crate::crypto::{Initiating, Replying};

use bytes::{Buf, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Grease {
    Fixed {
        #[serde(rename = "s")]
        at: usize,
        #[serde(rename = "l")]
        len: usize,
    },
    Vary {
        #[serde(rename = "s")]
        at: usize,
        #[serde(rename = "m")]
        min: usize,
        #[serde(rename = "M")]
        max: usize,
    },
}

#[derive(Serialize, Deserialize)]
pub struct PacketLayout {
    #[serde(rename = "m")]
    pub mask: u32, // general field mask
    pub o_ty: usize,   // offset of packet ty
    pub oi_eph: usize, // (initiating) offset of ephemeral key
    pub oi_epk: usize, // (initiating) offset of encrypted public key
    pub or_eph: usize, // (replying) offset of ephemeral key
    pub or_ets: usize, // (replying) offset of encrypted timestamp
    pub od_non: usize, // (data) offset of nonce
    pub od_dl: usize,  // (data) offset of data length
    pub od_d: usize,   // (data) offset of data itself
    #[serde(rename = "g")]
    pub grease: Vec<Grease>,
}

impl PacketLayout {
    pub fn check(&self) -> Result<(), &'static str> {
        let r = |x: usize, o: usize| x..x + o;
        #[rustfmt::skip]
        let ranges = [
            r(self.oi_eph, 32),
            r(self.oi_epk, 48),
            r(self.or_eph, 32),
            r(self.or_ets, 24),
            r(self.od_non, 12),
            r(self.od_dl, 4),
        ];

        let grease_ranges = self
            .grease
            .iter()
            .map(|g| match g {
                Grease::Fixed { at, len } => r(*at, *len),
                Grease::Vary { at, min: _, max } => r(*at, *max),
            })
            .collect::<Vec<_>>();

        // Data has a variable length, so reserve everything from od_d onward.
        if self.o_ty >= self.od_d
            || ranges[4..6]
                .iter()
                .chain(&grease_ranges)
                .any(|range| range.start < range.end && range.end > self.od_d)
        {
            return Err("data overlaps packet fields");
        }

        let ty_range = self.o_ty
            ..self
                .o_ty
                .checked_add(1)
                .ok_or("packet type offset overflows")?;
        for group in [0..2, 2..4, 4..6] {
            for (i, r1) in ranges[group.clone()]
                .iter()
                .chain(&grease_ranges)
                .chain(std::iter::once(&ty_range))
                .enumerate()
            {
                for (j, r2) in ranges[group.clone()]
                    .iter()
                    .chain(&grease_ranges)
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
        [self.oi_eph + 32, self.oi_epk + 48]
            .into_iter()
            .max()
            .unwrap()
    }

    fn rlen(&self) -> usize {
        [self.or_eph + 32, self.or_ets + 24]
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
            od_non: 1,
            od_dl: 1 + 12,
            od_d: 1 + 12 + 4,
            grease: vec![],
        }
    }
}

pub enum Packet {
    Initiating(Initiating),
    Reply(Replying),
    Data { nonce: [u8; 12], data: Bytes },
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Received unexpected packet type {0}")]
    UnexpectedTy(u8),
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

            let packet = Packet::Initiating(Initiating {
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

            let packet = Packet::Reply(Replying {
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
        todo!()
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
        let mut partial = BytesMut::from(&initiation[..80]);
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
        let mut partial = BytesMut::from(&reply[..56]);
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
        for grease in [
            Grease::Fixed { at: 81, len: 4 },
            Grease::Vary {
                at: 81,
                min: 1,
                max: 4,
            },
        ] {
            let mut layout = PacketLayout {
                o_ty: 84,
                od_d: 100,
                grease: vec![grease],
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err());
            layout.o_ty = 85;
            assert!(layout.check().is_ok());
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

        for grease in [
            Grease::Fixed { at: 81, len: 4 },
            Grease::Vary {
                at: 81,
                min: 1,
                max: 4,
            },
        ] {
            let mut layout = PacketLayout {
                od_d: 84,
                grease: vec![grease],
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err());
            layout.od_d = 85;
            assert!(layout.check().is_ok());
        }
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
        let mut src = BytesMut::from(&[0u8; 81][..]);
        let mut reply = vec![0; 57];
        reply[0] = 1;
        src.extend_from_slice(&reply[..56]);
        assert!(matches!(
            codec.decode(&mut src).unwrap(),
            Some(Packet::Initiating(_))
        ));
        let partial = src.clone();
        assert!(codec.decode(&mut src).unwrap().is_none());
        assert_eq!(src, partial);
        src.extend_from_slice(&reply[56..]);
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
}
