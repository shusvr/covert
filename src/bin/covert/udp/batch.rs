//! Linux nonblocking multi-message syscalls. Pointer-bearing headers never cross
//! an await: backing storage and all iovecs remain stable for the syscall only.
use crate::network::ReceiveBatch;
use bytes::Bytes;
use socket2::{SockAddr, SockAddrStorage};
use std::{
    io, mem,
    net::{Ipv4Addr, SocketAddr},
    os::fd::RawFd,
    ptr,
};

pub const BATCH_SIZE: usize = 32;

fn syscall(mut call: impl FnMut() -> libc::c_int) -> io::Result<usize> {
    loop {
        let result = call();
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub fn send(fd: RawFd, packets: &[(SocketAddr, Bytes)]) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    let count = packets.len().min(BATCH_SIZE);
    let addresses: [SockAddr; BATCH_SIZE] = std::array::from_fn(|i| {
        packets
            .get(i)
            .map_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), |p| p.0)
            .into()
    });
    let mut vectors: [libc::iovec; BATCH_SIZE] = std::array::from_fn(|i| {
        packets.get(i).map_or(
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            |(_, bytes)| libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            },
        )
    });
    let mut messages: [libc::mmsghdr; BATCH_SIZE] = std::array::from_fn(|i| {
        // Zeroed ancillary fields represent no control buffer and no flags.
        let mut header: libc::mmsghdr = unsafe { mem::zeroed() };
        header.msg_hdr.msg_name = addresses[i].as_ptr().cast_mut().cast();
        header.msg_hdr.msg_namelen = addresses[i].len();
        header.msg_hdr.msg_iov = &mut vectors[i];
        header.msg_hdr.msg_iovlen = 1;
        header
    });
    // SAFETY: every header references stable addresses, iovecs and immutable
    // packet bytes, which sendmmsg only reads, for the duration of this call.
    let sent = syscall(|| unsafe {
        libc::sendmmsg(
            fd,
            messages.as_mut_ptr(),
            count as _,
            (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as _,
        )
    })?;
    if sent == 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "sendmmsg made no progress",
        ));
    }
    tracing::trace!(packets = sent, "Sent UDP batch");
    Ok(sent)
}

pub fn receive(fd: RawFd, batch: &mut ReceiveBatch<SocketAddr>) -> io::Result<()> {
    if batch.slot_size == 0 || batch.buffer.len() < batch.slot_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty receive slots",
        ));
    }
    let count = (batch.buffer.len() / batch.slot_size).min(BATCH_SIZE);
    let mut addresses: [SockAddrStorage; BATCH_SIZE] =
        std::array::from_fn(|_| SockAddrStorage::zeroed());
    let mut vectors: [libc::iovec; BATCH_SIZE] = std::array::from_fn(|i| {
        if i < count {
            let bytes = &mut batch.buffer[i * batch.slot_size..(i + 1) * batch.slot_size];
            libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            }
        } else {
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            }
        }
    });
    let mut messages: [libc::mmsghdr; BATCH_SIZE] = std::array::from_fn(|i| {
        let mut header: libc::mmsghdr = unsafe { mem::zeroed() };
        header.msg_hdr.msg_name = (&mut addresses[i] as *mut SockAddrStorage).cast();
        header.msg_hdr.msg_namelen = addresses[i].size_of();
        header.msg_hdr.msg_iov = &mut vectors[i];
        header.msg_hdr.msg_iovlen = 1;
        header
    });
    // SAFETY: receive slots are disjoint and writable; address storage and iovec
    // arrays stay in place. DONTWAIT plus a null timeout never waits to fill a batch.
    let received = syscall(|| unsafe {
        libc::recvmmsg(
            fd,
            messages.as_mut_ptr(),
            count as _,
            libc::MSG_DONTWAIT as _,
            ptr::null_mut(),
        )
    })?;
    tracing::trace!(packets = received, "Received UDP batch");
    for (i, (address, message)) in addresses
        .into_iter()
        .zip(messages)
        .take(received)
        .enumerate()
    {
        let len = message.msg_len as usize;
        if message.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 || len > batch.slot_size {
            tracing::trace!("Discarding truncated UDP datagram");
            continue;
        }
        if message.msg_hdr.msg_namelen > address.size_of() {
            continue;
        }
        // SAFETY: the UDP socket/kernel supplied this initialized IP address and
        // its length into zero-initialized, sufficiently large address storage.
        let address = unsafe { SockAddr::new(address, message.msg_hdr.msg_namelen) };
        if let Some(address) = address.as_socket() {
            let start = i * batch.slot_size;
            batch.packets.push((address, start..start + len));
        }
    }
    Ok(())
}
