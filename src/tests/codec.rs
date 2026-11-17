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
        assert!(layout.ilen() <= 130, "sparse initiation: {layout:?}");
        assert!(layout.rlen() <= 76, "sparse reply: {layout:?}");
        assert!(
            usize::from(layout.odd) <= 44,
            "sparse data header: {layout:?}"
        );
    }
}

#[test]
fn test_parse_handshake_packets() {
    let layout = PacketLayout::default();
    let mut initiation = vec![0; layout.ilen()];
    initiation[usize::from(layout.oieph)..usize::from(layout.oieph) + 32].fill(7);
    initiation[usize::from(layout.oiepk)..usize::from(layout.oiepk) + 48].fill(8);
    initiation[usize::from(layout.oiets)..usize::from(layout.oiets) + 24].fill(10);
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
    reply[usize::from(layout.oty)] = 1;
    reply[usize::from(layout.oreph)..usize::from(layout.oreph) + 32].fill(9);
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
            let mut packet = vec![0; usize::from(layout.odd)];
            packet[usize::from(layout.oty)] = 2 ^ mask as u8;
            for (i, byte) in 0x12345678u32.to_be_bytes().into_iter().enumerate() {
                packet[usize::from(layout.odri) + i] = byte ^ mask.to_be_bytes()[i % 4];
            }
            for (i, byte) in 0x0123456789abcdefu64.to_be_bytes().into_iter().enumerate() {
                packet[usize::from(layout.odct) + i] = byte ^ mask.to_be_bytes()[i % 4];
            }
            for (i, byte) in (payload.len() as u32).to_be_bytes().into_iter().enumerate() {
                packet[usize::from(layout.oddl) + i] = byte ^ mask.to_be_bytes()[i % 4];
            }
            packet[usize::from(layout.odf)] = DataFlags::JUNK.bits() ^ mask.to_be_bytes()[0];
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
            assert_eq!(flags.bits(), DataFlags::JUNK.bits());
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
    let mut reply = vec![0; 57];
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
fn test_padding_lengths_and_partial_packets() {
    for padding in [0, 1, 28, 41, 109, 256] {
        let layout = PacketLayout {
            oip: padding,
            orp: padding,
            odp: padding,
            ..PacketLayout::default()
        };
        let serialized = layout.to_string();
        assert_eq!(
            serialized.parse::<PacketLayout>().unwrap().to_string(),
            serialized
        );
        for (packet, natural_len) in [
            (
                Packet::Initiating(Initiating {
                    ephemeral: [7; 32],
                    enc_pub_key: [8; 48],
                    enc_ts: [9; 24],
                    sender_idx: 1,
                }),
                109,
            ),
            (
                Packet::Reply(Replying {
                    eph: [7; 32],
                    auth_tag: [11; 16],
                    sender_idx: 1,
                    receiver_idx: 2,
                }),
                57,
            ),
            (
                Packet::Data(Data {
                    receiver_idx: 2,
                    flags: DataFlags::empty(),
                    counter: 1,
                    ciphertext: vec![3; 10],
                }),
                28,
            ),
        ] {
            let mut encoded = BytesMut::new();
            append(&mut encoded, packet, &layout).unwrap();
            assert_eq!(encoded.len(), natural_len.max(usize::from(padding)));
            for len in 0..encoded.len() {
                let mut partial = BytesMut::from(&encoded[..len]);
                let original = partial.clone();
                assert!(parse(&mut partial, &layout).is_none());
                assert_eq!(partial, original);
            }
            encoded.extend_from_slice(b"trailing");
            assert!(parse(&mut encoded, &layout).unwrap().is_ok());
            assert_eq!(&encoded[..], b"trailing");
        }
    }
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
        ..PacketLayout::default()
    });
    for layout in layouts
        .into_iter()
        .chain(layouts.map(|layout| PacketLayout {
            oip: 160,
            orp: 120,
            odp: 64,
            ..layout
        }))
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
                    auth_tag: [11; 16],
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
        assert_eq!(packet.auth_tag, [11; 16]);
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

#[test]
fn layout_parser_rejects_unknown_overlapping_and_out_of_range_fields() {
    for invalid in [
        "typo=7",
        "m=oops",
        "m=1&mask=2",
        "oty=1",
        "oieph=0",
        "odd=12",
        "oieph=256",
        "odctr=256",
        "oty=65536",
        "oip=65536",
        "orp=65536",
        "odp=65536",
        "oip=18446744073709551615",
    ] {
        assert!(
            invalid.parse::<PacketLayout>().is_err(),
            "accepted invalid layout: {invalid}"
        );
    }
    let maximum: PacketLayout = "oip=65535&orp=65535&odp=65535".parse().unwrap();
    assert_eq!(
        (maximum.oip, maximum.orp, maximum.odp),
        (u16::MAX, u16::MAX, u16::MAX)
    );
    assert_eq!(
        "".parse::<PacketLayout>().unwrap().to_string(),
        PacketLayout::default().to_string()
    );
}

#[test]
fn narrow_offsets_are_widened_before_size_arithmetic() {
    let layout: PacketLayout = "oieph=240&oreph=240".parse().unwrap();
    assert_eq!(layout.ilen(), 272);
    assert_eq!(layout.rlen(), 288);
    for packet in [
        Packet::Initiating(Initiating {
            ephemeral: [1; 32],
            enc_pub_key: [2; 48],
            enc_ts: [3; 24],
            sender_idx: 4,
        }),
        Packet::Reply(Replying {
            eph: [1; 32],
            sender_idx: 2,
            receiver_idx: 3,
            auth_tag: [4; 16],
        }),
        Packet::Data(Data {
            receiver_idx: 1,
            counter: 2,
            flags: DataFlags::empty(),
            ciphertext: vec![7; 1500],
        }),
    ] {
        let bytes = packet.to_bytes(&layout).unwrap();
        let (decoded, consumed) = parse_slice(&bytes, &layout).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        match decoded {
            Packet::Initiating(p) => assert_eq!(p.ephemeral, [1; 32]),
            Packet::Reply(p) => assert_eq!(p.eph, [1; 32]),
            Packet::Data(p) => assert_eq!(p.ciphertext, vec![7; 1500]),
        }
    }
}
