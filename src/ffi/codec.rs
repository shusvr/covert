//! Packet layouts, encoding, decoding and packet handles.
use super::*;
use crate::codec::{self, Data, Packet, PacketLayout};
free_handle!(covert_layout_free, PacketLayout);
free_handle!(covert_packet_free, Packet);

pub(super) fn clone_packet(p: &Packet) -> Packet {
    match p {
        Packet::Initiating(p) => Packet::Initiating(p.clone()),
        Packet::Reply(p) => Packet::Reply(*p),
        Packet::Data(p) => Packet::Data(Data {
            receiver_idx: p.receiver_idx,
            counter: p.counter,
            ciphertext: p.ciphertext.clone(),
        }),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_layout_new(
    text: *const u8,
    len: usize,
    out: *mut *mut PacketLayout,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let text = std::str::from_utf8(unsafe { bytes(text, len)? })
            .map_err(|_| Error::InvalidArgument("invalid FFI argument"))?;
        let layout = if text.is_empty() {
            PacketLayout::default()
        } else {
            text.parse()
                .map_err(|_| Error::InvalidArgument("invalid FFI argument"))?
        };
        layout
            .check()
            .map_err(|_| Error::InvalidArgument("invalid FFI argument"))?;
        *out = Box::into_raw(Box::new(layout));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_layout_random(out: *mut *mut PacketLayout) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = Box::into_raw(Box::new(PacketLayout::random()));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_layout_string(
    layout: *const PacketLayout,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        output(out, unsafe { get(layout)? }.to_string().into_bytes());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_codec_parse(
    layout: *const PacketLayout,
    data: *const u8,
    len: usize,
    consumed: *mut usize,
    out: *mut *mut Packet,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let consumed = unsafe { get_mut(consumed)? };
        *out = ptr::null_mut();
        *consumed = 0;
        let (p, n) = codec::parse_slice(unsafe { bytes(data, len)? }, unsafe { get(layout)? })
            .ok_or(Error::Empty)??;
        *out = Box::into_raw(Box::new(p));
        *consumed = n;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_codec_encode(
    layout: *const PacketLayout,
    packet: *const Packet,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let v = clone_packet(unsafe { get(packet)? }).to_bytes(unsafe { get(layout)? })?;
        output(out, v.to_vec());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_packet_data_new(
    index: u32,
    counter: u64,
    data: *const u8,
    len: usize,
    out: *mut *mut Packet,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let p = Packet::Data(Data {
            receiver_idx: index,
            counter,
            ciphertext: unsafe { bytes(data, len)? }.to_vec(),
        });
        *out = Box::into_raw(Box::new(p));
        Ok(())
    })
}
/// Kind: initiation=0, reply=1, data=2.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_packet_kind(packet: *const Packet, kind: *mut u32) -> i32 {
    guard(|| {
        *unsafe { get_mut(kind)? } = match unsafe { get(packet)? } {
            Packet::Initiating(_) => 0,
            Packet::Reply(_) => 1,
            Packet::Data(_) => 2,
        };
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_packet_data(
    packet: *const Packet,
    index: *mut u32,
    counter: *mut u64,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let index = unsafe { get_mut(index)? };
        let counter = unsafe { get_mut(counter)? };
        let out = unsafe { get_mut(out)? };
        let Packet::Data(p) = (unsafe { get(packet)? }) else {
            return Err(Error::InvalidArgument("invalid FFI argument"));
        };
        *index = p.receiver_idx;
        *counter = p.counter;
        output(out, p.ciphertext.clone());
        Ok(())
    })
}
