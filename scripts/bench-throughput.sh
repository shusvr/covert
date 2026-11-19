#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/bench-throughput.sh [--plain] [-- IPERF3_CLIENT_OPTIONS...]

By default, build covert in release mode and benchmark TCP throughput through
two VPN peers in separate Linux network namespaces joined by a veth pair.
With --plain, run bare iperf3 over the same namespace/veth topology instead.
Both modes use a 1400-byte MTU for iperf3 traffic (TUN in VPN mode, veth in
plain mode); the VPN's underlying veth pair uses a 1500-byte MTU.

Examples:
  scripts/bench-throughput.sh
  scripts/bench-throughput.sh --plain
  scripts/bench-throughput.sh -- -t 30 -P 4
  scripts/bench-throughput.sh --plain -- -t 30 -P 4 -R
  scripts/bench-throughput.sh -- -u -b 100M -l 1200

Client options are passed to iperf3; its default test duration is 10 seconds.
The script manages client/server mode, addresses, and the port itself.
VPN mode additionally requires cargo, ping, and /dev/net/tun.
Both modes require bash, iperf3, ip, ss, and root access (via sudo). Processes
and namespaces are cleaned up on exit. Run as your normal user; only network
setup and peers use sudo.
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null || die "Required command not found: $1"
}

plain=false
iperf_args=()
while (($#)); do
    case "$1" in
        --plain) plain=true; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; iperf_args+=("$@"); break ;;
        *) iperf_args+=("$1"); shift ;;
    esac
done

for arg in "${iperf_args[@]}"; do
    case "$arg" in
        -c*|--client*|-s|--server|-p*|--port*|-B*|--bind*|-D|--daemon|-I*|--pidfile*|-h|--help|-v|--version)
            die "The script manages connection options; unsupported client argument: $arg" ;;
    esac
done

require iperf3
require ss
require ip
root=()
namespaces=()
processes=()
veth_created=false
workdir=$(mktemp -d -t covert-bench.XXXXXXXX)
chmod 700 "$workdir"

cleanup() {
    local status=$? ns pid log
    local -a namespace_pids=()
    trap - EXIT INT TERM
    set +e

    # Kill namespace members, including children of sudo/ip netns exec.
    for ns in "${namespaces[@]}"; do
        mapfile -t namespace_pids < <("${root[@]}" ip netns pids "$ns" 2>/dev/null)
        if ((${#namespace_pids[@]})); then
            "${root[@]}" kill -TERM -- "${namespace_pids[@]}" 2>/dev/null
        fi
    done
    for pid in "${processes[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    for ns in "${namespaces[@]}"; do
        mapfile -t namespace_pids < <("${root[@]}" ip netns pids "$ns" 2>/dev/null)
        if ((${#namespace_pids[@]})); then
            "${root[@]}" kill -KILL -- "${namespace_pids[@]}" 2>/dev/null
        fi
        "${root[@]}" ip netns delete "$ns" 2>/dev/null
    done
    if "$veth_created"; then
        "${root[@]}" ip link delete "$veth_a" 2>/dev/null
    fi
    for pid in "${processes[@]}"; do
        wait "$pid" 2>/dev/null
    done
    if ((status != 0)); then
        for log in "$workdir"/*.log; do
            [[ -s "$log" ]] || continue
            printf '\n--- %s ---\n' "${log##*/}" >&2
            tail -n 20 "$log" >&2
        done
    fi
    rm -rf -- "$workdir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

payload_mtu=1400
link_mtu=1500
if "$plain"; then
    link_mtu=$payload_mtu
fi
port=5201

if ! "$plain"; then
    require cargo
    require ping
    [[ -c /dev/net/tun ]] || die '/dev/net/tun is unavailable; VPN mode needs Linux TUN support'

    repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    printf 'Building release VPN...\n' >&2
    cargo build --release --bin covert --manifest-path "$repo/Cargo.toml" \
        --target-dir "$repo/target" >&2
    binary="$repo/target/release/covert"
fi

if ((EUID != 0)); then
    require sudo
    sudo -v
    root=(sudo)
fi

ns_a="covert-bench-$$-$RANDOM-a"
ns_b="${ns_a%-a}-b"
veth_a="cv${RANDOM}a"
veth_b="${veth_a%a}b"
"${root[@]}" ip netns add "$ns_a"
namespaces+=("$ns_a")
"${root[@]}" ip netns add "$ns_b"
namespaces+=("$ns_b")
"${root[@]}" ip link add "$veth_a" type veth peer name "$veth_b"
veth_created=true
"${root[@]}" ip link set "$veth_a" netns "$ns_a"
"${root[@]}" ip link set "$veth_b" netns "$ns_b"
"${root[@]}" ip -n "$ns_a" link set lo up
"${root[@]}" ip -n "$ns_b" link set lo up
"${root[@]}" ip -n "$ns_a" addr add 192.0.2.1/30 dev "$veth_a"
"${root[@]}" ip -n "$ns_b" addr add 192.0.2.2/30 dev "$veth_b"
"${root[@]}" ip -n "$ns_a" link set "$veth_a" mtu "$link_mtu" up
"${root[@]}" ip -n "$ns_b" link set "$veth_b" mtu "$link_mtu" up

server_prefix=("${root[@]}" ip netns exec "$ns_b")
client_prefix=("${root[@]}" ip netns exec "$ns_a")
server_addr=192.0.2.2
client_addr=192.0.2.1

if ! "$plain"; then
    keys_a=$("$binary" genkey)
    keys_b=$("$binary" genkey)
    private_a=${keys_a#Private key: }
    private_a=${private_a%%$'\n'*}
    public_a=${keys_a##*Public key: }
    private_b=${keys_b#Private key: }
    private_b=${private_b%%$'\n'*}
    public_b=${keys_b##*Public key: }

    write_config() {
        local name=$1 local_ip=$2 private=$3 remote_ip=$4 public=$5 endpoint=$6
        # 1400 leaves room for protocol, AEAD, UDP, and IPv4 overhead on a 1500 MTU.
        cat >"$workdir/$name.toml" <<EOF
[Interface]
Address = "$local_ip/30"
Mtu = $payload_mtu
PrivateKey = "$private"

[Interface.Listener.Udp]
Port = 40676

[[Peer]]
AllowedIPs = "$remote_ip/32"
PublicKey = "$public"

[Peer.Transport.Udp]
Endpoint = "$endpoint:40676"
EOF
    }
    write_config bench-a 10.111.111.1 "$private_a" 10.111.111.2 "$public_b" 192.0.2.2
    write_config bench-b 10.111.111.2 "$private_b" 10.111.111.1 "$public_a" 192.0.2.1

    "${root[@]}" ip netns exec "$ns_a" env RUST_LOG=warn \
        "$binary" run "$workdir/bench-a.toml" >"$workdir/vpn-a.log" 2>&1 &
    vpn_a=$!
    processes+=("$vpn_a")
    "${root[@]}" ip netns exec "$ns_b" env RUST_LOG=warn \
        "$binary" run "$workdir/bench-b.toml" >"$workdir/vpn-b.log" 2>&1 &
    vpn_b=$!
    processes+=("$vpn_b")

    server_addr=10.111.111.2
    client_addr=10.111.111.1
    printf 'Waiting for the VPN tunnel (up to 30 probes)...\n' >&2
    ready=false
    for ((attempt = 0; attempt < 30; attempt++)); do
        kill -0 "$vpn_a" "$vpn_b" 2>/dev/null || die 'A VPN peer exited during startup'
        if "${client_prefix[@]}" ping -n -c 1 -w 1 -I "$client_addr" "$server_addr" >"$workdir/vpn-probe.log" 2>&1; then
            ready=true
            break
        fi
        sleep 0.1
    done
    "$ready" || die 'VPN tunnel did not become ready'
    printf 'Benchmarking release VPN: %s -> %s (TUN MTU %s, veth MTU %s)\n' \
        "$client_addr" "$server_addr" "$payload_mtu" "$link_mtu" >&2
else
    printf 'Benchmarking bare iperf3: %s -> %s (veth MTU %s)\n' \
        "$client_addr" "$server_addr" "$payload_mtu" >&2
fi

"${server_prefix[@]}" iperf3 --server --one-off --bind "$server_addr" \
    --port "$port" >"$workdir/iperf3-server.log" 2>&1 &
server_pid=$!
processes+=("$server_pid")
ready=false
for ((attempt = 0; attempt < 100; attempt++)); do
    kill -0 "$server_pid" 2>/dev/null || die 'iperf3 server exited during startup'
    if [[ -n $("${server_prefix[@]}" ss -H -ltn "sport = :$port") ]]; then
        ready=true
        break
    fi
    sleep 0.1
done
"$ready" || die 'iperf3 server did not become ready'

"${client_prefix[@]}" iperf3 --client "$server_addr" --bind "$client_addr" \
    --port "$port" "${iperf_args[@]}" &
client_pid=$!
processes+=("$client_pid")
wait "$client_pid"
wait "$server_pid"
