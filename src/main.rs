#![allow(unused, dead_code)]

use etherparse::{IcmpEchoHeader, Icmpv4Header, Icmpv4Slice, Icmpv4Type, IpSlice, PacketBuilder};
use serde::{Deserialize, Deserializer};
use socket2::{Domain, MaybeUninitSlice, Protocol, SockAddr, SockAddrStorage, Socket, Type};
use std::{
    env::args,
    error::Error,
    fs::read_to_string,
    mem::{MaybeUninit, transmute},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    str::FromStr,
    sync::Arc,
};

#[derive(Debug, Deserialize)]
struct Config {
    id: u16,
    #[serde(deserialize_with = "read_addr")]
    source: Ipv4Addr,
    #[serde(deserialize_with = "read_addr")]
    destination: Ipv4Addr,
    inbound_port: u16,
    outbound_port: u16,
}

fn read_addr<'de, D: Deserializer<'de>>(de: D) -> Result<Ipv4Addr, D::Error> {
    let s = String::deserialize(de)?;
    Ipv4Addr::from_str(&s).map_err(serde::de::Error::custom)
}

fn outbound(cfg: Arc<Config>, udp: UdpSocket, icmp: Socket) {
    let mut buf = [0; 1500];
    let mut packet = Vec::with_capacity(1500);

    let mut i = 1;
    loop {
        let (len, from) = match udp.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("ERR: {e}");
                continue;
            }
        };

        // wireguard packet
        let payload = &buf[..len];

        let header = Icmpv4Header::with_checksum(
            Icmpv4Type::EchoRequest(IcmpEchoHeader { id: cfg.id, seq: i }),
            payload,
        );
        i += 1;

        packet.resize(header.header_len() + payload.len(), 0);
        packet.clear();

        header.write(&mut packet);
        packet.extend_from_slice(payload);

        let addr = SockAddr::from(SocketAddrV4::new(cfg.destination, 0));

        match icmp.send_to(&packet, &addr) {
            Ok(_) => println!("Sent ICMP: plen={}", payload.len()),
            Err(e) => eprintln!("Failed to send ICMP: {e}"),
        }
    }
}

fn inbound(cfg: Arc<Config>, udp: UdpSocket, icmp: Socket) {
    let mut buf = MaybeUninit::<[u8; 1500]>::zeroed();
    loop {
        let (len, from) = icmp
            .recv_from(buf.as_mut())
            .expect("Failed to recv from icmp");

        let packet = unsafe { &buf.assume_init_ref()[..len] };
        let ip = IpSlice::from_slice(packet).unwrap();
        let x = Icmpv4Slice::from_slice(ip.payload().payload).unwrap();

        let [a, b, c, d] = x.bytes5to8();
        let id = ((a as u16) << 8) | (b as u16);
        let seq = ((c as u16) << 8) | (d as u16);

        if id == cfg.id {
            let wg_packet = x.payload();
            udp.send_to(wg_packet, (Ipv4Addr::LOCALHOST, cfg.outbound_port))
                .unwrap();
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cfg_path = args().nth(1).expect("Expected config name");
    let cfg = Arc::new(toml::from_str::<Config>(&read_to_string(&cfg_path)?)?);

    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, cfg.inbound_port))?;
    let icmp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;

    let t1 = std::thread::spawn({
        let cfg = cfg.clone();
        let udp = udp.try_clone()?;
        let icmp = icmp.try_clone()?;
        move || outbound(cfg, udp, icmp)
    });

    let t2 = std::thread::spawn(move || inbound(cfg, udp, icmp));

    t1.join();
    t2.join();

    Ok(())
}
