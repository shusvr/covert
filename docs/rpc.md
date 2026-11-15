Run with a read-only Unix-socket status stream:

```sh
covert run co1.toml -r
covert run co1.toml -r ./rpc.sock
covert run co1.toml --rpc /run/covert.co1.sock
```

A bare `-r` / `--rpc` uses `dirs::runtime_dir()` and the filename
`covert.<devname>.sock` directly within that directory. On Linux this is normally
`$XDG_RUNTIME_DIR`. Put the config filename before a bare flag because the flag
also accepts an optional path. An unavailable runtime directory, missing parent,
unwritable path, or existing path (including a stale socket) is a startup error.
No directories are created and existing files are never removed to make room.

Sockets have mode `0600`. On graceful exit, or a later startup failure, Covert
removes the socket it created. It leaves a replacement file/socket untouched.

Connect with a Unix-socket client, for example:

```sh
socat - UNIX-CONNECT:./rpc.sock
```

Each client receives one JSON object per line immediately and every second:

```json
{"session":"de305d54-75b4-431b-adb2-eb6b9e546014","peers":[{"id":"59549789-2354-4dde-a27b-3cbef6f1f3d7","psk":true,"allowed_ips":["10.111.111.2/32"],"transport":"udp","status":"connected","first_established_at":1794754800000,"last_established_at":1794755100000,"sent":12000,"received":9000}]}
```

- `session` is a random UUID for this process run, shared by all clients.
- Every configured peer is present, including disconnected peers. `transport`
  is the configured tag, falling back to the listener tag for learned peers.
- Establishment times are Unix milliseconds and are `null` before a handshake.
- `sent` counts plaintext IP bytes accepted by the transport sender, including
  flushed queued traffic. An asynchronous transport can subsequently drop a
  packet: this is not an on-wire delivery counter.
- `received` counts authenticated, non-junk plaintext IP bytes. Handshakes,
  keepalives, invalid packets, and transport/encryption overhead are excluded.
- Byte totals and first establishment time survive disconnects and rekeys;
  they reset when the process restarts. The last establishment time updates on
  each handshake. Expired sessions report `disconnected`.

The stream accepts no commands and does not expose private keys or PSKs.
