WebRTC carries Covert packets in a real binary data channel, using ICE connectivity checks, certificate-based DTLS, SCTP and DCEP. The channel is unordered with zero retransmissions; Covert's authenticated handshake and encryption still run inside it. SCTP handles fragmentation of larger messages, including packet-layout padding.

Replace the interface's listener with:

```toml
[Interface.Listener.Webrtc.webrtc]
Port = 40676
IceServers = []
```

On the initiating peer, configure the other machine's **TCP signaling** address:

```toml
[Peer.Transport.Webrtc.webrtc]
Endpoint = "192.0.2.1:40676"
```

On the responder, omit Endpoint (or omit Transport entirely). Use the usual matching keys and AllowedIPs. Either side can send VPN data after negotiation. Port defaults to 40676; 0 chooses an ephemeral signaling listener port. IceServers defaults to an empty list; optional STUN URLs such as `stun:stun.example.org:3478` help discover public candidates. Authenticated TURN server configuration is not currently exposed.

Allow the signaling TCP port and the UDP ports selected by ICE through the firewall. The signaling port is not the UDP data port. Both sides behind restrictive NAT may require additional network configuration. No external signaling service is required: Covert exchanges length-prefixed JSON SDP descriptions directly over TCP, with a 30-second negotiation deadline and a 64-KiB SDP limit. Failed outgoing negotiations retry through normal peer maintenance. An established data channel can carry VPN rekeys without renegotiating WebRTC.

This is a WebRTC **data** application, not simulated audio/video. Packet timings, candidate addresses, the signaling protocol and application behavior remain observable; it does not impersonate a browser or a particular conferencing service. SDP signaling is plaintext and has no separate authentication; Covert's configured keys authenticate tunnel peers before inner traffic is delivered. DTLS certificates are checked against the exchanged SDP fingerprint, not a public CA.
