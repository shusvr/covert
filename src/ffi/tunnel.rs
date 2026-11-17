//! Low-level tunnel handles.
use super::codec::clone_packet;
use super::*;
use crate::{
    codec::{Packet, PacketLayout},
    config::Liveness,
    tunnel::Tunnel,
};
free_handle!(covert_tunnel_free, Tunnel);

#[repr(C)]
pub struct TunnelLiveness {
    pub timeout: u64,
    pub max_age: u64,
    pub ka_delay: u32,
    pub ka_jitter: u32,
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_tunnel_process(t: *mut Tunnel, flush_on_err: u8) -> i32 {
    guard(|| {
        if flush_on_err > 1 {
            return Err(INVALID);
        }
        unsafe { get_mut(t)? }
            .process_new_packets(flush_on_err != 0)
            .map_err(|_| FAILED)
    })
}
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
