//! Cryptographic primitives and cipher handles.
use super::*;
use crate::{
    codec::Packet,
    crypto::{self, Cipher},
};
free_handle!(covert_cipher_free, Cipher);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_crypto_keypair(secret: *mut u8, public: *mut u8) -> i32 {
    guard(|| {
        if secret.is_null() || public.is_null() {
            return Err(Error::InvalidArgument("invalid FFI argument"));
        }
        let sk = crypto::random_sk()?;
        let pk = sk.compute_public_key()?;
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
            return Err(Error::InvalidArgument("invalid FFI argument"));
        }
        let sk = crypto::to_sk(&unsafe { key(secret)? });
        let pk = sk.compute_public_key()?;
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
        )?;
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
            return Err(Error::InvalidArgument("invalid FFI argument"));
        }
        let Packet::Initiating(p) = (unsafe { get(initiation)? }) else {
            return Err(Error::InvalidArgument("invalid FFI argument"));
        };
        let (pk, ts) = crypto::pre_reply(&unsafe { key(secret)? }, p)?;
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
            return Err(Error::InvalidArgument("invalid FFI argument"));
        };
        let (r, c) = crypto::post_reply(
            &unsafe { key(public)? },
            unsafe { psk(shared)? }.as_ref(),
            index,
            p,
        )?;
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
            return Err(Error::InvalidArgument("invalid FFI argument"));
        };
        let Packet::Reply(r) = (unsafe { get(reply)? }) else {
            return Err(Error::InvalidArgument("invalid FFI argument"));
        };
        let c = crypto::finish(
            &unsafe { key(secret)? },
            unsafe { psk(shared)? }.as_ref(),
            i,
            r,
        )?;
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
        let (n, v) = unsafe { get(cipher)? }.encrypt(unsafe { bytes(data, len)? }.to_vec())?;
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
        let v = unsafe { get(cipher)? }.decrypt(counter, unsafe { bytes(data, len)? }.to_vec())?;
        output(out, v);
        Ok(())
    })
}
