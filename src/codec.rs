use crate::crypto::{Initiating, Replying};

use bitflags::bitflags;
use bytes::{Buf, Bytes, BytesMut};
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
    oip: 0,
    orp: 0,
    odp: 0,
};

macro_rules! mkconfig {
    ($( $(#[$($fattr:tt)*])? $fname:ident: $fty:ty),* $(,)?) => {
        #[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct PacketLayout {
            $($(#[$($fattr)*])? pub $fname: $fty),*
        }

        impl PacketLayout {
            fn apply(self, patch: PacketLayoutPatch) -> Self {
                Self {
                    $($fname: patch.$fname.unwrap_or(self.$fname)),*
                }
            }
        }

        #[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct PacketLayoutPatch {
            $($(#[$($fattr)*])? pub $fname: Option<$fty>),*
        }
    };
}

mkconfig! {
    #[serde(rename = "m", alias = "mask")]
    mask: u32,    // general field mask
    oty: u16,   // offset of packet ty
    oieph: u8, // (initiating) offset of ephemeral key
    oiepk: u8, // (initiating) offset of encrypted public key
    oiets: u8, // (initiating) offset of encrypted timestamp
    oisi: u8,  // (initiating) offset of sender index
    oip: u16,   // (initiating) pad to this len
    oreph: u8, // (replying) offset of ephemeral key
    orsi: u8,  // (replying) offset of sender index
    orri: u8,  // (replying) offset of receiver index
    orp: u16,   // (replying) pad to this len
    odri: u8,  // (data) offset of receiver index
    odct: u8,  // (data) offset of counter
    odf: u8,   // (data) offset of flags
    oddl: u8,  // (data) offset of data length
    odd: u8,   // (data) offset of data itself
    odp: u16,   // (data) pad to this minimum total length
}

impl Default for PacketLayout {
    fn default() -> Self {
        DEFAULT_LAYOUT
    }
}

impl PacketLayout {
    pub fn to_string(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

impl FromStr for PacketLayout {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let patch = serde_urlencoded::from_str(s).map_err(Error::LayoutParseErr)?;
        let layout = DEFAULT_LAYOUT.apply(patch);
        layout.check()?;
        Ok(layout)
    }
}

impl PacketLayout {
    pub fn random() -> Self {
        // Keep shuffled headers compact: at most four unused bytes per gap.
        const MAX_PADDING: usize = 4;

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
            oty: oty as _,
            oieph: oieph as _,
            oiepk: oiepk as _,
            oiets: oiets as _,
            oisi: oisi as _,
            oreph: oreph as _,
            orsi: orsi as _,
            orri: orri as _,
            odri: odri as _,
            odct: odct as _,
            odf: odf as _,
            oddl: oddl as _,
            odd: (data_end + fastrand::usize(0..=MAX_PADDING))
                .try_into()
                .expect("generated offset fits field type"),
            oip: 0,
            orp: 0,
            odp: 0,
        }
    }

    pub fn check(&self) -> Result<(), Error> {
        let r = |s: &'static str, x: usize, o: usize| (s, x..x + o);
        #[rustfmt::skip]
        let ranges = [
            r("oieph", usize::from(self.oieph), 32),
            r("oiepk", usize::from(self.oiepk), 48),
            r("oisi", usize::from(self.oisi), 4),
            r("oiets", usize::from(self.oiets), 24),
            r("oreph", usize::from(self.oreph), 32),
            r("orsi", usize::from(self.orsi), 4),
            r("orri", usize::from(self.orri), 4),
            r("odri", usize::from(self.odri), 4),
            r("odctr", usize::from(self.odct), 8),
            r("oddl", usize::from(self.oddl), 4),
            r("odf", usize::from(self.odf), 1),
        ];

        // Data has a variable length, so reserve everything from od_d onward.
        if usize::from(self.oty) >= usize::from(self.odd) {
            return Err(Error::LayoutFieldsOverlap(
                "odd".to_owned(),
                "oty".to_owned(),
            ));
        } else {
            if let Some(bad) = ranges[7..11].iter().find_map(|(name, range)| {
                (range.start < range.end && range.end > usize::from(self.odd)).then_some(name)
            }) {
                return Err(Error::LayoutFieldsOverlap(
                    "odd".to_owned(),
                    (*bad).to_owned(),
                ));
            }
        }

        let ty_range = (
            "oty",
            usize::from(self.oty)
                ..usize::from(self.oty)
                    .checked_add(1)
                    .expect("packet type overflow"),
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
            usize::from(self.oieph) + 32,
            usize::from(self.oiepk) + 48,
            usize::from(self.oisi) + 4,
            usize::from(self.oiets) + 24,
            usize::from(self.oip),
        ]
        .into_iter()
        .max()
        .unwrap()
    }

    // Authentication follows the last reply field, before optional padding.
    fn reply_tag_offset(&self) -> usize {
        [
            usize::from(self.oreph) + 32,
            usize::from(self.orsi) + 4,
            usize::from(self.orri) + 4,
            usize::from(self.oty) + 1,
        ]
        .into_iter()
        .max()
        .unwrap()
    }

    fn rlen(&self) -> usize {
        (self.reply_tag_offset() + 16).max(usize::from(self.orp))
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct DataFlags : u8 {
        const JUNK = 1;
    }
}

#[derive(Debug)]
pub struct Data {
    pub receiver_idx: u32,
    pub flags: DataFlags,
    pub counter: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum Packet {
    Initiating(Initiating),
    Reply(Replying),
    Data(Data),
}

impl Packet {
    pub fn to_bytes(self, layout: &PacketLayout) -> Result<Bytes, Error> {
        let mut buf = BytesMut::new();
        append(&mut buf, self, layout)?;
        Ok(buf.freeze())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Received unexpected packet type {0}")]
    UnexpectedTy(u8),
    #[error("Tried encoding a packet that is too large")]
    PacketOverflow,
    #[error("Invalid packet layout({0})")]
    InvalidLayout(&'static str),
    #[error("Failed to parse layout: {0}")]
    LayoutParseErr(serde_urlencoded::de::Error),
    #[error("Layout param `{0}` doesn't exist")]
    UnkownLayoutParam(String),
    #[error("Layout params `{0}` and `{1}` will cause overlap")]
    LayoutFieldsOverlap(String, String),

    #[error("Io: {0}")]
    Io(#[from] io::Error),
}

/// Consumes one complete packet, leaving incomplete or invalid input untouched.
pub fn parse(buf: &mut BytesMut, layout: &PacketLayout) -> Option<Result<Packet, Error>> {
    match parse_slice(buf, layout)? {
        Ok((packet, consumed)) => {
            buf.advance(consumed);
            Some(Ok(packet))
        }
        Err(err) => Some(Err(err)),
    }
}

/// Parses a borrowed packet without copying the encoded header or advancing a buffer.
pub fn parse_slice(buf: &[u8], layout: &PacketLayout) -> Option<Result<(Packet, usize), Error>> {
    if buf.len() < usize::from(layout.oty) + 1 {
        return None;
    }

    let ty = buf[usize::from(layout.oty)] ^ layout.mask as u8;
    match ty {
        // initiating
        0 => {
            let ephemeral = get_masked_at(buf, usize::from(layout.oieph), layout.mask)?;
            let enc_pub_key = get_masked_at(buf, usize::from(layout.oiepk), layout.mask)?;

            let sender_idx =
                u32::from_be_bytes(get_masked_at(buf, usize::from(layout.oisi), layout.mask)?);
            let enc_ts = get_masked_at(buf, usize::from(layout.oiets), layout.mask)?;
            let packet = Packet::Initiating(Initiating {
                enc_ts,
                sender_idx,
                enc_pub_key,
                ephemeral,
            });
            let consumed = layout.ilen().max(usize::from(layout.oty) + 1);
            if buf.len() < consumed {
                return None;
            }
            return Some(Ok((packet, consumed)));
        }
        // reply
        1 => {
            let ephemeral = get_masked_at(buf, usize::from(layout.oreph), layout.mask)?;

            let sender_idx =
                u32::from_be_bytes(get_masked_at(buf, usize::from(layout.orsi), layout.mask)?);
            let receiver_idx =
                u32::from_be_bytes(get_masked_at(buf, usize::from(layout.orri), layout.mask)?);
            let packet = Packet::Reply(Replying {
                sender_idx,
                receiver_idx,
                eph: ephemeral,
                auth_tag: get_masked_at(buf, layout.reply_tag_offset(), layout.mask)?,
            });
            let consumed = layout.rlen().max(usize::from(layout.oty) + 1);
            if buf.len() < consumed {
                return None;
            }
            return Some(Ok((packet, consumed)));
        }
        // data
        2 => {
            let receiver_idx =
                u32::from_be_bytes(get_masked_at(buf, usize::from(layout.odri), layout.mask)?);
            let counter =
                u64::from_be_bytes(get_masked_at(buf, usize::from(layout.odct), layout.mask)?);
            let flags = DataFlags::from_bits_retain(
                get_masked_at::<1>(buf, usize::from(layout.odf), layout.mask)?[0],
            );
            let len =
                u32::from_be_bytes(get_masked_at(buf, usize::from(layout.oddl), layout.mask)?);
            let end = usize::from(layout.odd).checked_add(usize::try_from(len).ok()?)?;
            let consumed = end
                .max(usize::from(layout.odri).checked_add(4)?)
                .max(usize::from(layout.odct).checked_add(8)?)
                .max(usize::from(layout.odf).checked_add(1)?)
                .max(usize::from(layout.oddl).checked_add(4)?)
                .max(usize::from(layout.oty).checked_add(1)?)
                .max(usize::from(layout.odp));
            if buf.len() < consumed {
                return None;
            }
            let data = buf[usize::from(layout.odd)..end].to_vec();

            return Some(Ok((
                Packet::Data(Data {
                    receiver_idx,
                    flags,
                    counter,
                    ciphertext: data,
                }),
                consumed,
            )));
        }
        _ => return Some(Err(Error::UnexpectedTy(ty))),
    }
}

/// Appends a packet using layout-relative offsets, randomizing unused bytes.
/// Pads to the corresponding `oip`, `orp`, or `odp` minimum total length;
/// packets already at or above that length are never truncated.
/// The layout must have passed `PacketLayout::check`.
pub fn append(buf: &mut BytesMut, packet: Packet, layout: &PacketLayout) -> Result<(), Error> {
    let ty_end = usize::from(layout.oty)
        .checked_add(1)
        .ok_or(Error::PacketOverflow)?;
    let (ty, len) = match &packet {
        Packet::Initiating(_) => (0, layout.ilen().max(ty_end)),
        Packet::Reply(_) => (1, layout.rlen().max(ty_end)),
        Packet::Data(Data {
            ciphertext: data, ..
        }) => {
            u32::try_from(data.len()).map_err(|_| Error::PacketOverflow)?;
            let len = usize::from(layout.odd)
                .checked_add(data.len())
                .ok_or(Error::PacketOverflow)?
                .max(
                    usize::from(layout.odri)
                        .checked_add(4)
                        .ok_or(Error::PacketOverflow)?,
                )
                .max(
                    usize::from(layout.odct)
                        .checked_add(8)
                        .ok_or(Error::PacketOverflow)?,
                )
                .max(
                    usize::from(layout.odf)
                        .checked_add(1)
                        .ok_or(Error::PacketOverflow)?,
                )
                .max(
                    usize::from(layout.oddl)
                        .checked_add(4)
                        .ok_or(Error::PacketOverflow)?,
                )
                .max(ty_end)
                .max(usize::from(layout.odp));
            (2, len)
        }
    };
    let start = buf.len();
    let end = start.checked_add(len).ok_or(Error::PacketOverflow)?;
    buf.resize(end, 0);
    fastrand::fill(&mut buf[start..end]);
    let out = &mut buf[start..end];
    out[usize::from(layout.oty)] = ty ^ layout.mask as u8;
    match packet {
        Packet::Initiating(Initiating {
            enc_pub_key,
            ephemeral,
            sender_idx,
            enc_ts,
        }) => {
            put_masked_at(out, usize::from(layout.oiets), &enc_ts, layout.mask);
            put_masked_at(
                out,
                usize::from(layout.oisi),
                &sender_idx.to_be_bytes(),
                layout.mask,
            );
            put_masked_at(out, usize::from(layout.oieph), &ephemeral, layout.mask);
            put_masked_at(out, usize::from(layout.oiepk), &enc_pub_key, layout.mask);
        }
        Packet::Reply(Replying {
            eph,
            sender_idx,
            receiver_idx,
            auth_tag,
        }) => {
            put_masked_at(out, layout.reply_tag_offset(), &auth_tag, layout.mask);
            put_masked_at(
                out,
                usize::from(layout.orsi),
                &sender_idx.to_be_bytes(),
                layout.mask,
            );
            put_masked_at(
                out,
                usize::from(layout.orri),
                &receiver_idx.to_be_bytes(),
                layout.mask,
            );
            put_masked_at(out, usize::from(layout.oreph), &eph, layout.mask);
        }
        Packet::Data(Data {
            receiver_idx,
            flags,
            counter,
            ciphertext: data,
        }) => {
            put_masked_at(
                out,
                usize::from(layout.odri),
                &receiver_idx.to_be_bytes(),
                layout.mask,
            );
            put_masked_at(
                out,
                usize::from(layout.odct),
                &counter.to_be_bytes(),
                layout.mask,
            );
            put_masked_at(out, usize::from(layout.odf), &[flags.bits()], layout.mask);
            put_masked_at(
                out,
                usize::from(layout.oddl),
                &(data.len() as u32).to_be_bytes(),
                layout.mask,
            );
            out[usize::from(layout.odd)..usize::from(layout.odd) + data.len()]
                .copy_from_slice(&data);
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
#[path = "./tests/codec.rs"]
mod tests;
