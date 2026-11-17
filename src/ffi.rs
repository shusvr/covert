//! C ABI for crypto, codec, and the sans-I/O tunnel. See `include/covert.h`.
//!
//! # Safety
//! All non-null pointers must be aligned, valid for their documented size and
//! lifetime, and have the indicated type. Handles must originate here and be
//! freed exactly once. Calls involving a handle must be externally serialized.
//! Output locations must be writable and must not alias inputs or each other.
//! Never pass a live output buffer/handle as an output slot: free it first.
//! Null byte pointers are allowed only with zero length; null PSKs mean no PSK.
//! Panics are caught, but do not protect against invalid pointers or aborts.
#![allow(clippy::missing_safety_doc)]

use crate::{
    codec::{self, Data, DataFlags, Packet, PacketLayout},
    config::Liveness,
    crypto::{self, Cipher, Key},
    sans::Tunnel,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

pub const OK: i32 = 0;
pub const EMPTY: i32 = 1;
pub const INVALID: i32 = -1;
pub const FAILED: i32 = -2;
pub const PANIC: i32 = -3;
type Result<T = ()> = std::result::Result<T, i32>;

#[repr(C)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
}
#[repr(C)]
pub struct TunnelLiveness {
    pub timeout: u64,
    pub max_age: u64,
    pub ka_delay: u32,
    pub ka_jitter: u32,
}

fn guard(f: impl FnOnce() -> Result) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => OK,
        Ok(Err(e)) => e,
        Err(_) => PANIC,
    }
}
unsafe fn get<'a, T>(p: *const T) -> Result<&'a T> {
    unsafe { p.as_ref() }.ok_or(INVALID)
}
unsafe fn get_mut<'a, T>(p: *mut T) -> Result<&'a mut T> {
    unsafe { p.as_mut() }.ok_or(INVALID)
}
unsafe fn bytes<'a>(p: *const u8, n: usize) -> Result<&'a [u8]> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() || n > isize::MAX as usize {
        return Err(INVALID);
    }
    Ok(unsafe { slice::from_raw_parts(p, n) })
}
unsafe fn key(p: *const u8) -> Result<Key> {
    Ok(unsafe { bytes(p, 32)? }.try_into().unwrap())
}
unsafe fn psk(p: *const u8) -> Result<Option<Key>> {
    if p.is_null() {
        Ok(None)
    } else {
        Ok(Some(unsafe { key(p)? }))
    }
}
fn output(out: &mut Buffer, data: Vec<u8>) {
    let data = data.into_boxed_slice();
    out.len = data.len();
    out.data = Box::into_raw(data).cast::<u8>();
}
fn clone_packet(p: &Packet) -> Packet {
    match p {
        Packet::Initiating(p) => Packet::Initiating(p.clone()),
        Packet::Reply(p) => Packet::Reply(*p),
        Packet::Data(p) => Packet::Data(Data {
            receiver_idx: p.receiver_idx,
            counter: p.counter,
            flags: DataFlags::from_bits_retain(p.flags.bits()),
            ciphertext: p.ciphertext.clone(),
        }),
    }
}
macro_rules! free_handle {
    ($name:ident, $ty:ty) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(p: *mut $ty) -> i32 {
            guard(|| {
                if !p.is_null() {
                    unsafe {
                        drop(Box::from_raw(p));
                    }
                }
                Ok(())
            })
        }
    };
}
free_handle!(covert_layout_free, PacketLayout);
free_handle!(covert_packet_free, Packet);
free_handle!(covert_cipher_free, Cipher);
free_handle!(covert_tunnel_free, Tunnel);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_buffer_free(p: *mut Buffer) -> i32 {
    guard(|| {
        let p = unsafe { get_mut(p)? };
        if !p.data.is_null() {
            unsafe {
                drop(Box::from_raw(ptr::slice_from_raw_parts_mut(p.data, p.len)));
            }
        }
        p.data = ptr::null_mut();
        p.len = 0;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_keypair(secret: *mut u8, public: *mut u8) -> i32 {
    guard(|| {
        if secret.is_null() || public.is_null() {
            return Err(INVALID);
        }
        let sk = crypto::random_sk().map_err(|_| FAILED)?;
        let pk = sk.compute_public_key().map_err(|_| FAILED)?;
        unsafe {
            ptr::copy_nonoverlapping(crypto::sk_to_bytes(&sk).as_ptr(), secret, 32);
            ptr::copy_nonoverlapping(pk.as_ref().as_ptr(), public, 32);
        }
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_public_key(secret: *const u8, public: *mut u8) -> i32 {
    guard(|| {
        if public.is_null() {
            return Err(INVALID);
        }
        let sk = crypto::to_sk(&unsafe { key(secret)? });
        let pk = sk.compute_public_key().map_err(|_| FAILED)?;
        unsafe {
            ptr::copy_nonoverlapping(pk.as_ref().as_ptr(), public, 32);
        }
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_initiate(
    secret: *const u8,
    public: *const u8,
    timestamp: u64,
    index: u32,
    out: *mut *mut Packet,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let p = crypto::initiate(
            &unsafe { key(secret)? },
            &unsafe { key(public)? },
            timestamp,
            index,
        )
        .map_err(|_| FAILED)?;
        *out = Box::into_raw(Box::new(Packet::Initiating(p)));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_pre_reply(
    secret: *const u8,
    initiation: *const Packet,
    public: *mut u8,
    timestamp: *mut u64,
) -> i32 {
    guard(|| {
        let timestamp = unsafe { get_mut(timestamp)? };
        if public.is_null() {
            return Err(INVALID);
        }
        let Packet::Initiating(p) = (unsafe { get(initiation)? }) else {
            return Err(INVALID);
        };
        let (pk, ts) = crypto::pre_reply(&unsafe { key(secret)? }, p).map_err(|_| FAILED)?;
        unsafe {
            ptr::copy_nonoverlapping(pk.as_ptr(), public, 32);
        }
        *timestamp = ts;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_post_reply(
    public: *const u8,
    shared: *const u8,
    index: u32,
    initiation: *const Packet,
    reply: *mut *mut Packet,
    cipher: *mut *mut Cipher,
) -> i32 {
    guard(|| {
        let reply = unsafe { get_mut(reply)? };
        let cipher = unsafe { get_mut(cipher)? };
        *reply = ptr::null_mut();
        *cipher = ptr::null_mut();
        let Packet::Initiating(p) = (unsafe { get(initiation)? }) else {
            return Err(INVALID);
        };
        let (r, c) = crypto::post_reply(
            &unsafe { key(public)? },
            unsafe { psk(shared)? }.as_ref(),
            index,
            p,
        )
        .map_err(|_| FAILED)?;
        let r = Box::new(Packet::Reply(r));
        let c = Box::new(c);
        *reply = Box::into_raw(r);
        *cipher = Box::into_raw(c);
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_finish(
    secret: *const u8,
    shared: *const u8,
    initiation: *const Packet,
    reply: *const Packet,
    out: *mut *mut Cipher,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let Packet::Initiating(i) = (unsafe { get(initiation)? }) else {
            return Err(INVALID);
        };
        let Packet::Reply(r) = (unsafe { get(reply)? }) else {
            return Err(INVALID);
        };
        let c = crypto::finish(
            &unsafe { key(secret)? },
            unsafe { psk(shared)? }.as_ref(),
            i,
            r,
        )
        .map_err(|_| FAILED)?;
        *out = Box::into_raw(Box::new(c));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_encrypt(
    cipher: *const Cipher,
    data: *const u8,
    len: usize,
    counter: *mut u64,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let counter = unsafe { get_mut(counter)? };
        let (n, v) = unsafe { get(cipher)? }
            .encrypt(unsafe { bytes(data, len)? }.to_vec())
            .map_err(|_| FAILED)?;
        *counter = n;
        output(out, v);
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_decrypt(
    cipher: *const Cipher,
    counter: u64,
    data: *const u8,
    len: usize,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let v = unsafe { get(cipher)? }
            .decrypt(counter, unsafe { bytes(data, len)? }.to_vec())
            .map_err(|_| FAILED)?;
        output(out, v);
        Ok(())
    })
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
        let text = std::str::from_utf8(unsafe { bytes(text, len)? }).map_err(|_| INVALID)?;
        let layout = if text.is_empty() {
            PacketLayout::default()
        } else {
            text.parse().map_err(|_| INVALID)?
        };
        layout.check().map_err(|_| INVALID)?;
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
            .ok_or(EMPTY)?
            .map_err(|_| FAILED)?;
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
        let v = clone_packet(unsafe { get(packet)? })
            .to_bytes(unsafe { get(layout)? })
            .map_err(|_| FAILED)?;
        output(out, v.to_vec());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_packet_data_new(
    index: u32,
    counter: u64,
    flags: u8,
    data: *const u8,
    len: usize,
    out: *mut *mut Packet,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let flags = DataFlags::from_bits(flags).ok_or(INVALID)?;
        let p = Packet::Data(Data {
            receiver_idx: index,
            counter,
            flags,
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
    flags: *mut u8,
    out: *mut Buffer,
) -> i32 {
    guard(|| {
        let index = unsafe { get_mut(index)? };
        let counter = unsafe { get_mut(counter)? };
        let flags = unsafe { get_mut(flags)? };
        let out = unsafe { get_mut(out)? };
        let Packet::Data(p) = (unsafe { get(packet)? }) else {
            return Err(INVALID);
        };
        *index = p.receiver_idx;
        *counter = p.counter;
        *flags = p.flags.bits();
        output(out, p.ciphertext.clone());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_new(
    layout: *const PacketLayout,
    secret: *const u8,
    public: *const u8,
    shared: *const u8,
    liveness: *const TunnelLiveness,
    out: *mut *mut Tunnel,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let l = unsafe { get(liveness)? };
        let t = Tunnel::new(
            *unsafe { get(layout)? },
            unsafe { key(secret)? },
            Liveness {
                timeout: l.timeout,
                max_age: l.max_age,
                ka_delay: l.ka_delay,
                ka_jitter: l.ka_jitter,
            },
            unsafe { key(public)? },
            unsafe { psk(shared)? },
        );
        *out = Box::into_raw(Box::new(t));
        Ok(())
    })
}
macro_rules! tunnel_action {
    ($name:ident, $method:ident $(, ($($aname:ident: $aty:ty),* $(,)?))?) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(t: *mut Tunnel $(, $($aname: $aty)*)?) -> i32 {
            guard(|| unsafe { get_mut(t)? }.$method($($($aname),*)?).map_err(|_| FAILED))
        }
    };
}
tunnel_action!(covert_tunnel_initiate, initiate);
tunnel_action!(covert_tunnel_process, process_new_packets, (flush_on_err: bool));
macro_rules! tunnel_write {
    ($name:ident, $method:ident) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(t: *mut Tunnel, data: *const u8, len: usize) -> i32 {
            guard(|| {
                unsafe { get_mut(t)? }.$method(unsafe { bytes(data, len)? });
                Ok(())
            })
        }
    };
}
tunnel_write!(covert_tunnel_push, push_packet);
tunnel_write!(covert_tunnel_write_incoming, write_incoming);
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_process_packet(
    t: *mut Tunnel,
    packet: *const Packet,
) -> i32 {
    guard(|| {
        unsafe { get_mut(t)? }
            .process_incoming_packet(clone_packet(unsafe { get(packet)? }))
            .map_err(|_| FAILED)
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_read_outbound(t: *mut Tunnel, out: *mut Buffer) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let v = unsafe { get_mut(t)? }
            .read_outbound()
            .map_err(|_| FAILED)?
            .ok_or(EMPTY)?;
        output(out, v.to_vec());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_read_packet(t: *mut Tunnel, out: *mut Buffer) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        let v = unsafe { get_mut(t)? }.read_packet().ok_or(EMPTY)?;
        output(out, v);
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_read_outbound_packet(
    t: *mut Tunnel,
    out: *mut *mut Packet,
) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = ptr::null_mut();
        let p = unsafe { get_mut(t)? }.read_outbound_packet().ok_or(EMPTY)?;
        *out = Box::into_raw(Box::new(p));
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_is_live(t: *const Tunnel, out: *mut u8) -> i32 {
    guard(|| {
        *unsafe { get_mut(out)? } = u8::from(unsafe { get(t)? }.is_live());
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_local_index(t: *const Tunnel, out: *mut u32) -> i32 {
    guard(|| {
        let out = unsafe { get_mut(out)? };
        *out = unsafe { get(t)? }.local_index().ok_or(EMPTY)?;
        Ok(())
    })
}
