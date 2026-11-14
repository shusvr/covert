use crate::crypto::{Initiating, Replying};

use bitflags::bitflags;
use bytes::{Buf, BytesMut};
use futures::channel::mpsc;
use std::{io, str::FromStr};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

const DEFAULT_LAYOUT: PacketLayout = PacketLayout {
    mask: 0,
    oty: 0,
    oieph: 1,
    oiepk: 1 + 32,
    oreph: 1,
    oiets: 85,
    oisi: 81,
    orsi: 33,
    orri: 37,
    odri: 1,
    odct: 5,
    odf: 13,
    oddl: 14,
    odd: 18,
};

#[derive(Debug, Clone, Copy)]
pub struct PacketLayout {
    pub mask: u32,    // general field mask
    pub oty: usize,   // offset of packet ty
    pub oieph: usize, // (initiating) offset of ephemeral key
    pub oiepk: usize, // (initiating) offset of encrypted public key
    pub oiets: usize, // (initiating) offset of encrypted timestamp
    pub oisi: usize,  // (initiating) offset of sender index
    pub oreph: usize, // (replying) offset of ephemeral key
    pub orsi: usize,  // (replying) offset of sender index
    pub orri: usize,  // (replying) offset of receiver index
    pub odri: usize,  // (data) offset of receiver index
    pub odct: usize,  // (data) offset of counter
    pub odf: usize,   // (data) offset of flags
    pub oddl: usize,  // (data) offset of data length
    pub odd: usize,   // (data) offset of data itself
}

impl Default for PacketLayout {
    fn default() -> Self {
        DEFAULT_LAYOUT
    }
}

impl ToString for PacketLayout {
    fn to_string(&self) -> String {
        let pairs = [
            ("m", self.mask as usize),
            ("oty", self.oty),
            ("oieph", self.oieph),
            ("oiepk", self.oiepk),
            ("oiets", self.oiets),
            ("oisidx", self.oisi),
            ("oreph", self.oreph),
            ("orsidx", self.orsi),
            ("orridx", self.orri),
            ("odridx", self.odri),
            ("odctr", self.odct),
            ("oddl", self.oddl),
            ("odf", self.odf),
            ("odd", self.odd),
        ];

        let pairs = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>();
        pairs.join("&")
    }
}

impl FromStr for PacketLayout {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut layout = DEFAULT_LAYOUT;
        for pair in s.split('&') {
            let (k, v) = pair.split_once("=").ok_or(Error::InvalidLayout("pair"))?;
            let v = v
                .parse::<usize>()
                .map_err(|_| Error::InvalidLayout("non int"))?;

            match k {
                "m" => {
                    layout.mask =
                        u32::try_from(v).map_err(|_| Error::InvalidLayout("mask overflow"))?
                }
                "oty" => layout.oty = v,
                "oieph" => layout.oieph = v,
                "oiepk" => layout.oiepk = v,
                "oiets" => layout.oiets = v,
                "oisidx" => layout.oisi = v,
                "oreph" => layout.oreph = v,
                "orsidx" => layout.orsi = v,
                "orridx" => layout.orri = v,
                "odridx" => layout.odri = v,
                "odctr" => layout.odct = v,
                "oddl" => layout.oddl = v,
                "odf" => layout.odf = v,
                "odd" => layout.odd = v,
                _ => return Err(Error::UnkownLayoutParam(k.to_owned())),
            }
        }

        layout.check()?;
        Ok(layout)
    }
}

impl PacketLayout {
    pub fn random() -> Self {
        const MAX_PADDING: usize = 16;

        fn offsets<const N: usize>(oty: usize, sizes: [usize; N]) -> ([usize; N], usize) {
            let mut order = std::array::from_fn::<_, N, _>(|i| i);
            fastrand::shuffle(&mut order);
            let mut offsets = [0; N];
            let mut end = 0;
            for i in order {
                let mut start = end + fastrand::usize(0..=MAX_PADDING);
                if start <= oty && oty < start + sizes[i] {
                    start = oty + 1;
                }
                offsets[i] = start;
                end = start + sizes[i];
            }
            (offsets, end.max(oty + 1))
        }

        let oty = fastrand::usize(0..=MAX_PADDING);
        let ([oieph, oiepk, oiets, oisi], _) = offsets(oty, [32, 48, 24, 4]);
        let ([oreph, orsi, orri], _) = offsets(oty, [32, 4, 4]);
        let ([odri, odct, odf, oddl], data_end) = offsets(oty, [4, 8, 1, 4]);
        Self {
            mask: fastrand::u32(..),
            oty,
            oieph,
            oiepk,
            oiets,
            oisi,
            oreph,
            orsi,
            orri,
            odri,
            odct,
            odf,
            oddl,
            odd: data_end + fastrand::usize(0..=MAX_PADDING),
        }
    }

    pub fn check(&self) -> Result<(), Error> {
        let r = |s: &'static str, x: usize, o: usize| (s, x..x + o);
        #[rustfmt::skip]
        let ranges = [
            r("oieph", self.oieph, 32),
            r("oiepk", self.oiepk, 48),
            r("oisidx", self.oisi, 4),
            r("oiets", self.oiets, 24),
            r("oreph", self.oreph, 32),
            r("orsidx", self.orsi, 4),
            r("orridx", self.orri, 4),
            r("odridx", self.odri, 4),
            r("odctr", self.odct, 8),
            r("oddl", self.oddl, 4),
            r("odf", self.odf, 1),
        ];

        // Data has a variable length, so reserve everything from od_d onward.
        if self.oty >= self.odd {
            return Err(Error::LayoutFieldsOverlap(
                "odd".to_owned(),
                "oty".to_owned(),
            ));
        } else {
            if let Some(bad) = ranges[7..11].iter().find_map(|(name, range)| {
                (range.start < range.end && range.end > self.odd).then_some(name)
            }) {
                return Err(Error::LayoutFieldsOverlap(
                    "odd".to_owned(),
                    (*bad).to_owned(),
                ));
            }
        }

        let ty_range = (
            "oty",
            self.oty..self.oty.checked_add(1).expect("packet type overflow"),
        );
        for group in [0..4, 4..7, 7..11] {
            for (i, (k1, r1)) in ranges[group.clone()]
                .iter()
                .chain(std::iter::once(&ty_range))
                .enumerate()
            {
                for (j, (k2, r2)) in ranges[group.clone()]
                    .iter()
                    .chain(std::iter::once(&ty_range))
                    .enumerate()
                {
                    let overlaps = (r1.start < r2.end) & (r2.start < r1.end);
                    if i != j && overlaps {
                        return Err(Error::LayoutFieldsOverlap(
                            (*k1).to_owned(),
                            (*k2).to_owned(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

impl PacketLayout {
    fn ilen(&self) -> usize {
        [
            self.oieph + 32,
            self.oiepk + 48,
            self.oisi + 4,
            self.oiets + 24,
        ]
        .into_iter()
        .max()
        .unwrap()
    }

    fn rlen(&self) -> usize {
        [self.oreph + 32, self.orsi + 4, self.orri + 4]
            .into_iter()
            .max()
            .unwrap()
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct DataFlags : u8 {
        const KEEPALIVE = 1;
    }

}

#[derive(Debug)]
pub struct Data {
    pub(crate) receiver_idx: u32,
    pub(crate) flags: DataFlags,
    pub(crate) counter: u64,
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum Packet {
    Initiating(Initiating),
    Reply(Replying),
    Data(Data),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Received unexpected packet type {0}")]
    UnexpectedTy(u8),
    #[error("Tried encoding a packet that is too large")]
    PacketOverflow,
    #[error("Invalid packet layout({0})")]
    InvalidLayout(&'static str),
    #[error("Layout param `{0}` doesn't exist")]
    UnkownLayoutParam(String),
    #[error("Layout params `{0}` and `{1}` will cause overlap")]
    LayoutFieldsOverlap(String, String),
    #[error("Channel was closed or full")]
    ChannelError(#[from] mpsc::SendError),
    #[error("Io: {0}")]
    Io(#[from] io::Error),
}

/// Consumes one complete packet, leaving incomplete or invalid input untouched.
pub fn parse(buf: &mut BytesMut, layout: &PacketLayout) -> Option<Result<Packet, Error>> {
    if buf.len() < layout.oty + 1 {
        return None;
    }

    let ty = buf[layout.oty] ^ layout.mask as u8;
    match ty {
        // initiating
        0 => {
            let ephemeral = get_masked_at(buf, layout.oieph, layout.mask)?;
            let enc_pub_key = get_masked_at(buf, layout.oiepk, layout.mask)?;

            let sender_idx = u32::from_be_bytes(get_masked_at(buf, layout.oisi, layout.mask)?);
            let enc_ts = get_masked_at(buf, layout.oiets, layout.mask)?;
            let packet = Packet::Initiating(Initiating {
                enc_ts,
                sender_idx,
                enc_pub_key,
                ephemeral,
            });
            let consumed = layout.ilen().max(layout.oty + 1);
            buf.advance(consumed);
            return Some(Ok(packet));
        }
        // reply
        1 => {
            let ephemeral = get_masked_at(buf, layout.oreph, layout.mask)?;

            let sender_idx = u32::from_be_bytes(get_masked_at(buf, layout.orsi, layout.mask)?);
            let receiver_idx = u32::from_be_bytes(get_masked_at(buf, layout.orri, layout.mask)?);
            let packet = Packet::Reply(Replying {
                sender_idx,
                receiver_idx,
                eph: ephemeral,
            });
            let consumed = layout.rlen().max(layout.oty + 1);
            buf.advance(consumed);
            return Some(Ok(packet));
        }
        // data
        2 => {
            let receiver_idx = u32::from_be_bytes(get_masked_at(buf, layout.odri, layout.mask)?);
            let counter = u64::from_be_bytes(get_masked_at(buf, layout.odct, layout.mask)?);
            let flags =
                DataFlags::from_bits_retain(get_masked_at::<1>(buf, layout.odf, layout.mask)?[0]);
            let len = u32::from_be_bytes(get_masked_at(buf, layout.oddl, layout.mask)?);
            let end = layout.odd.checked_add(usize::try_from(len).ok()?)?;
            let consumed = end
                .max(layout.odri.checked_add(4)?)
                .max(layout.odct.checked_add(8)?)
                .max(layout.odf.checked_add(1)?)
                .max(layout.oddl.checked_add(4)?)
                .max(layout.oty.checked_add(1)?);
            if buf.len() < consumed {
                return None;
            }
            let data = buf[layout.odd..end].to_vec();
            buf.advance(consumed);

            return Some(Ok(Packet::Data(Data {
                receiver_idx,
                flags,
                counter,
                ciphertext: data,
            })));
        }
        _ => return Some(Err(Error::UnexpectedTy(ty))),
    }
}

/// Appends a packet using layout-relative offsets, randomizing unused bytes.
/// The layout must have passed `PacketLayout::check`.
pub fn append(buf: &mut BytesMut, packet: Packet, layout: &PacketLayout) -> Result<(), Error> {
    let ty_end = layout.oty.checked_add(1).ok_or(Error::PacketOverflow)?;
    let (ty, len) = match &packet {
        Packet::Initiating(_) => (0, layout.ilen().max(ty_end)),
        Packet::Reply(_) => (1, layout.rlen().max(ty_end)),
        Packet::Data(Data {
            ciphertext: data, ..
        }) => {
            u32::try_from(data.len()).map_err(|_| Error::PacketOverflow)?;
            let len = layout
                .odd
                .checked_add(data.len())
                .ok_or(Error::PacketOverflow)?
                .max(layout.odri.checked_add(4).ok_or(Error::PacketOverflow)?)
                .max(layout.odct.checked_add(8).ok_or(Error::PacketOverflow)?)
                .max(layout.odf.checked_add(1).ok_or(Error::PacketOverflow)?)
                .max(layout.oddl.checked_add(4).ok_or(Error::PacketOverflow)?)
                .max(ty_end);
            (2, len)
        }
    };
    let start = buf.len();
    let end = start.checked_add(len).ok_or(Error::PacketOverflow)?;
    buf.resize(end, 0);
    fastrand::fill(&mut buf[start..end]);
    let out = &mut buf[start..end];
    out[layout.oty] = ty ^ layout.mask as u8;
    match packet {
        Packet::Initiating(Initiating {
            enc_pub_key,
            ephemeral,
            sender_idx,
            enc_ts,
        }) => {
            put_masked_at(out, layout.oiets, &enc_ts, layout.mask);
            put_masked_at(out, layout.oisi, &sender_idx.to_be_bytes(), layout.mask);
            put_masked_at(out, layout.oieph, &ephemeral, layout.mask);
            put_masked_at(out, layout.oiepk, &enc_pub_key, layout.mask);
        }
        Packet::Reply(Replying {
            eph,
            sender_idx,
            receiver_idx,
        }) => {
            put_masked_at(out, layout.orsi, &sender_idx.to_be_bytes(), layout.mask);
            put_masked_at(out, layout.orri, &receiver_idx.to_be_bytes(), layout.mask);
            put_masked_at(out, layout.oreph, &eph, layout.mask);
        }
        Packet::Data(Data {
            receiver_idx,
            flags,
            counter,
            ciphertext: data,
        }) => {
            put_masked_at(out, layout.odri, &receiver_idx.to_be_bytes(), layout.mask);
            put_masked_at(out, layout.odct, &counter.to_be_bytes(), layout.mask);
            put_masked_at(out, layout.odf, &[flags.bits()], layout.mask);
            put_masked_at(
                out,
                layout.oddl,
                &(data.len() as u32).to_be_bytes(),
                layout.mask,
            );
            out[layout.odd..layout.odd + data.len()].copy_from_slice(&data);
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
    fn test_random_layout_wf() {
        fastrand::seed(100);

        for _ in 0..1024 {
            let layout = PacketLayout::random();
            assert!(layout.check().is_ok(), "{layout:?}");
        }
    }

    #[test]
    fn test_parse_handshake_packets() {
        let layout = PacketLayout::default();
        let mut initiation = vec![0; layout.ilen()];
        initiation[layout.oieph..layout.oieph + 32].fill(7);
        initiation[layout.oiepk..layout.oiepk + 48].fill(8);
        initiation[layout.oiets..layout.oiets + 24].fill(10);
        let mut buf = BytesMut::from(initiation.as_slice());
        let Packet::Initiating(packet) = parse(&mut buf, &layout).unwrap().unwrap() else {
            panic!("expected initiation");
        };
        assert_eq!(packet.ephemeral, [7; 32]);
        assert_eq!(packet.enc_pub_key, [8; 48]);
        assert_eq!(packet.enc_ts, [10; 24]);
        assert!(buf.is_empty());
        let mut partial = BytesMut::from(&initiation[..108]);
        let original = partial.clone();
        assert!(parse(&mut partial, &layout).is_none());
        assert_eq!(partial, original);

        let mut reply = vec![0; layout.rlen()];
        reply[layout.oty] = 1;
        reply[layout.oreph..layout.oreph + 32].fill(9);
        let mut buf = BytesMut::from(reply.as_slice());
        let Packet::Reply(packet) = parse(&mut buf, &layout).unwrap().unwrap() else {
            panic!("expected reply");
        };
        assert_eq!(packet.eph, [9; 32]);
        assert!(buf.is_empty());
        let mut partial = BytesMut::from(&reply[..40]);
        let original = partial.clone();
        assert!(parse(&mut partial, &layout).is_none());
        assert_eq!(partial, original);
    }

    #[test]
    fn test_type_layout_overlap() {
        // Check both ends of every fixed field in all packet variants.
        for o_ty in [1, 32, 33, 80, 56, 8, 9, 12] {
            let layout = PacketLayout {
                oty: o_ty,
                odd: 100,
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err(), "type offset {o_ty}");
        }
    }

    #[test]
    fn test_index_layout_overlap() {
        for layout in [
            PacketLayout {
                oisi: 0,
                ..PacketLayout::default()
            },
            PacketLayout {
                oisi: 78,
                ..PacketLayout::default()
            },
            PacketLayout {
                orsi: 31,
                ..PacketLayout::default()
            },
            PacketLayout {
                orri: 31,
                ..PacketLayout::default()
            },
            PacketLayout {
                orri: 36,
                ..PacketLayout::default()
            },
        ] {
            assert!(layout.check().is_err());
        }
    }

    #[test]
    fn test_data_receiver_index_overlap() {
        for od_ridx in [0, 4, 12, 16, 17] {
            let layout = PacketLayout {
                odri: od_ridx,
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err());
        }
    }

    #[test]
    fn test_data_layout_overlap() {
        for od_d in [0, 1, 8, 9, 12] {
            let layout = PacketLayout {
                odd: od_d,
                ..PacketLayout::default()
            };
            assert!(layout.check().is_err());
        }
        let layout = PacketLayout {
            oty: 17,
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
                let mut packet = vec![0; layout.odd];
                packet[layout.oty] = 2 ^ mask as u8;
                for (i, byte) in 0x12345678u32.to_be_bytes().into_iter().enumerate() {
                    packet[layout.odri + i] = byte ^ mask.to_be_bytes()[i % 4];
                }
                for (i, byte) in 0x0123456789abcdefu64.to_be_bytes().into_iter().enumerate() {
                    packet[layout.odct + i] = byte ^ mask.to_be_bytes()[i % 4];
                }
                for (i, byte) in (payload.len() as u32).to_be_bytes().into_iter().enumerate() {
                    packet[layout.oddl + i] = byte ^ mask.to_be_bytes()[i % 4];
                }
                packet[layout.odf] = DataFlags::KEEPALIVE.bits() ^ mask.to_be_bytes()[0];
                packet.extend_from_slice(payload);
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
                let Packet::Data(Data {
                    receiver_idx,
                    flags,
                    counter,
                    ciphertext: data,
                }) = parse(&mut buf, &layout).unwrap().unwrap()
                else {
                    panic!("expected data");
                };
                assert_eq!(receiver_idx, 0x12345678);
                assert_eq!(counter, 0x0123456789abcdef);
                assert_eq!(flags.bits(), DataFlags::KEEPALIVE.bits());
                assert_eq!(data, payload);
                assert_eq!(&buf[..], b"trailing");
            }
        }
    }

    #[test]
    fn test_decode_concatenated_packets() {
        let mut codec = Codec {
            layout: PacketLayout::default(),
        };
        let mut src = BytesMut::from(&[0u8; 109][..]);
        let mut reply = vec![0; 41];
        reply[0] = 1;
        src.extend_from_slice(&reply[..40]);
        assert!(matches!(
            codec.decode(&mut src).unwrap(),
            Some(Packet::Initiating(_))
        ));
        let partial = src.clone();
        assert!(codec.decode(&mut src).unwrap().is_none());
        assert_eq!(src, partial);
        src.extend_from_slice(&reply[40..]);
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
        let layouts = [0, 0x12345678].map(|mask| PacketLayout {
            mask,
            oty: 2,
            oieph: 5,
            oiepk: 40,
            oreph: 6,
            oiets: 100,
            oisi: 90,
            orsi: 70,
            orri: 80,
            odri: 14,
            odct: 5,
            odf: 19,
            oddl: 20,
            odd: 28,
        });
        for layout in layouts
            .into_iter()
            .chain((0..128).map(|_| PacketLayout::random()))
        {
            let mut codec = Codec::new(layout);
            codec.layout.check().unwrap();
            let mut buf = BytesMut::from(&b"prefix"[..]);
            codec
                .encode(
                    Packet::Initiating(Initiating {
                        sender_idx: 0x12345678,
                        enc_pub_key: [8; 48],
                        enc_ts: [10; 24],
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
                        eph: [9; 32],
                    }),
                    &mut buf,
                )
                .unwrap();
            for data in [b"payload".to_vec(), Vec::new()] {
                codec
                    .encode(
                        Packet::Data(Data {
                            flags: DataFlags::from_bits_retain(0x81),
                            receiver_idx: 0x12345678,
                            counter: u64::MAX,
                            ciphertext: data,
                        }),
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
            assert_eq!(packet.enc_ts, [10; 24]);
            assert_eq!(packet.ephemeral, [7; 32]);
            let Some(Packet::Reply(packet)) = codec.decode(&mut buf).unwrap() else {
                panic!("expected reply")
            };
            assert_eq!(packet.sender_idx, 0x87654321);
            assert_eq!(packet.receiver_idx, 0x12345678);
            assert_eq!(packet.eph, [9; 32]);
            for expected in [&b"payload"[..], &b""[..]] {
                let Some(Packet::Data(Data {
                    receiver_idx,
                    flags,
                    counter,
                    ciphertext: data,
                })) = codec.decode(&mut buf).unwrap()
                else {
                    panic!("expected data")
                };
                assert_eq!(receiver_idx, 0x12345678);
                assert_eq!(counter, u64::MAX);
                assert_eq!(flags.bits(), 0x81);
                assert_eq!(data, expected);
            }
            assert!(buf.is_empty());
        }
    }
}
