use bytes::Bytes;
use thiserror::Error;

use crate::Key;

#[derive(Debug, Clone, Copy)]
pub enum Grease {
    Fixed { at: usize, len: usize },
    Vary { at: usize, min: usize, max: usize },
}

pub struct PacketLayout {
    pub mask: u32,
    pub o_ty: usize,
    pub oi_eph: usize,
    pub oi_pk: usize,
    pub of_eph: usize,
    pub of_ets: usize,
    pub grease: Vec<Grease>,
}

impl PacketLayout {
    pub fn check(&self) -> Result<(), &'static str> {
        if [self.oi_eph, self.oi_pk, self.of_eph]
            .iter()
            .any(|x| *x <= self.o_ty)
        {
            return Err("packet ty offset (o_ty) must be before any variant field offsets");
        }

        let r = |x: usize, o: usize| x..x + o;
        #[rustfmt::skip]
        let ranges = [
            r(self.oi_eph, 32),
            r(self.oi_pk, 32),
            r(self.of_eph, 32),
            r(self.of_ets, 32),
        ];

        let grease_ranges = self
            .grease
            .iter()
            .map(|g| match g {
                Grease::Fixed { at, len } => r(*at, *len),
                Grease::Vary { at, min: _, max } => r(*at, *max),
            })
            .collect::<Vec<_>>();

        for group in [0..2, 2..4] {
            for (i, r1) in ranges[group.clone()]
                .iter()
                .chain(&grease_ranges)
                .enumerate()
            {
                for (j, r2) in ranges[group.clone()]
                    .iter()
                    .chain(&grease_ranges)
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
        [self.oi_eph + 32, self.oi_pk + 32]
            .into_iter()
            .max()
            .unwrap()
    }

    fn flen(&self) -> usize {
        [self.of_eph + 32, self.of_ets + 20]
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
            oi_pk: 1 + 32,
            of_eph: 1,
            of_ets: 1 + 32,
            grease: vec![],
        }
    }
}

pub enum Packet {
    Initiating { enc_pub_key: Key, ephemeral: Key },
    Finished { ephemeral: Key, enc_ts: [u8; 20] },
    Data { data: Bytes },
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Received unexpected packet type {0}")]
    UnexpectedTy(u8),
}

pub fn parse(buf: &[u8], layout: &PacketLayout) -> Option<Result<(Packet, usize), Error>> {
    if buf.len() < layout.o_ty + 1 {
        return None;
    }

    let ty = buf[layout.o_ty] & layout.mask as u8;
    match ty {
        // initiating
        0 => {
            let ephemeral = get_masked_at(buf, layout.oi_eph, layout.mask)?;
            let enc_pub_key = get_masked_at(buf, layout.oi_eph, layout.mask)?;

            let packet = Packet::Initiating {
                enc_pub_key,
                ephemeral,
            };
            return Some(Ok((packet, layout.ilen())));
        }
        // finished
        1 => {
            let ephemeral = get_masked_at(buf, layout.of_eph, layout.mask)?;
            let enc_ts = get_masked_at(buf, layout.of_ets, layout.mask)?;

            let packet = Packet::Finished { ephemeral, enc_ts };
            return Some(Ok((packet, layout.flen())));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_layout_wf() {
        let pl = PacketLayout::default();
        assert!(pl.check().is_ok());
    }
}
