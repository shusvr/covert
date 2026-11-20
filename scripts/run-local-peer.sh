#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat <<'HELP'
Usage: scripts/run-local-peer.sh examples/ex1.toml
       scripts/run-local-peer.sh examples/ex2.toml
       scripts/run-local-peer.sh --cleanup

Run the two example peers in separate terminals, in either order.
The first invocation creates two network namespaces joined by a veth pair.
Temporary config copies rewrite existing endpoints to use that link.
Peers without endpoints stay passive. Ctrl+C stops a peer. --cleanup removes the network after both
peers have stopped.

Run as your normal user. Network setup and Covert use sudo.
Requires iproute2, flock, Python 3.11+, Cargo, and /dev/net/tun.

Test from another terminal:
  sudo ip netns exec covert-local-$UID-1 ping 10.111.111.2
  sudo ip netns exec covert-local-$UID-2 ping 10.111.111.1
HELP
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

[[ ${1:-} != --help && ${1:-} != -h ]] || { usage; exit 0; }
(($# == 1)) || { usage >&2; exit 1; }
for command in ip flock python3; do
    command -v "$command" >/dev/null || die "Required command not found: $command"
done

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
state_dir="/tmp/covert-local-$UID"
mkdir -p -- "$state_dir"
[[ -d "$state_dir" && ! -L "$state_dir" && -O "$state_dir" ]] ||
    die "State directory must be owned by you: $state_dir"
chmod 700 "$state_dir"
exec 9>"$state_dir/network.lock"
exec 7>"$state_dir/setup.lock"

root=()
if ((EUID != 0)); then
    command -v sudo >/dev/null || die 'sudo is required'
    sudo -v
    root=(sudo)
fi
ns_a="covert-local-$UID-1"
ns_b="covert-local-$UID-2"

if [[ $1 == --cleanup ]]; then
    flock -x 7
    flock -n -x 9 || die 'Stop both local peers before cleaning up'
    [[ -f "$state_dir/ready" ]] || { printf 'No local peer network to clean up.\n'; exit 0; }
    for namespace in "$ns_a" "$ns_b"; do
        [[ -z $("${root[@]}" ip netns pids "$namespace") ]] ||
            die "Processes are still running in $namespace"
    done
    "${root[@]}" ip netns delete "$ns_a"
    "${root[@]}" ip netns delete "$ns_b"
    rm -- "$state_dir/ready"
    printf 'Removed local peer network.\n'
    exit 0
fi

config=$(realpath -- "$1")
[[ -f "$config" ]] || die "Config does not exist: $config"
case ${config##*/} in
    ex1.toml) peer=1; namespace=$ns_a; remote=192.0.2.2 ;;
    ex2.toml) peer=2; namespace=$ns_b; remote=192.0.2.1 ;;
    *) die 'Choose ex1.toml or ex2.toml' ;;
esac
[[ -c /dev/net/tun ]] || die '/dev/net/tun is unavailable'
command -v cargo >/dev/null || die 'cargo is required'
# Serialize builds and topology creation across the two terminals.
flock -x 7
cargo build --release --bin covert --manifest-path "$repo/Cargo.toml" --target-dir "$repo/target"
if [[ ! -f "$state_dir/ready" ]]; then
    for existing in "$ns_a" "$ns_b"; do
        if ip netns list | python3 -c 'import sys; sys.exit(0 if sys.argv[1] in [line.split()[0] for line in sys.stdin if line.strip()] else 1)' "$existing"; then
            die "Namespace already exists without our state marker: $existing"
        fi
    done
    created_a=false
    created_b=false
    setup_failed() {
        local status=$?
        trap - EXIT
        if "$created_b"; then "${root[@]}" ip netns delete "$ns_b" || true; fi
        if "$created_a"; then "${root[@]}" ip netns delete "$ns_a" || true; fi
        exit "$status"
    }
    trap setup_failed EXIT
    "${root[@]}" ip netns add "$ns_a"
    created_a=true
    "${root[@]}" ip netns add "$ns_b"
    created_b=true
    "${root[@]}" ip -n "$ns_a" link add cv-local-a type veth peer name cv-local-b
    "${root[@]}" ip -n "$ns_a" link set cv-local-b netns "$ns_b"
    "${root[@]}" ip -n "$ns_a" address add 192.0.2.1/30 dev cv-local-a
    "${root[@]}" ip -n "$ns_b" address add 192.0.2.2/30 dev cv-local-b
    "${root[@]}" ip -n "$ns_a" link set cv-local-a up
    "${root[@]}" ip -n "$ns_b" link set cv-local-b up
    "${root[@]}" ip -n "$ns_a" link set lo up
    "${root[@]}" ip -n "$ns_b" link set lo up
    touch "$state_dir/ready"
    trap - EXIT
fi
# A shared lock allows both peers to run while blocking --cleanup.
flock -s 9
flock -u 7
exec 8>"$state_dir/peer-$peer.lock"
flock -n -x 8 || die "Peer $peer is already running"
workdir=$(mktemp -d "$state_dir/peer-$peer.XXXXXXXX")
trap 'rm -rf -- "$workdir"' EXIT

python3 - "$config" "$workdir/ex$peer.toml" "$remote" <<'PY'
import pathlib
import re
import sys
import tomllib

source, destination, remote = sys.argv[1:]
text = pathlib.Path(source).read_text()
# The older second example used an array for its single transport table.
text = re.sub(r'^\[\[Peer\.Transport\.Udp\]\]\s*$', '[Peer.Transport.Udp]', text, flags=re.MULTILINE)
config = tomllib.loads(text)
listener = config["Interface"]["Listener"]
if set(listener) != {"Udp"}:
    raise SystemExit("Local examples must use UDP")
peers = config.get("Peer", [])
if len(peers) != 1:
    raise SystemExit("Local examples require exactly one peer")
# Each example listens on the same port in its own network namespace.
port = listener["Udp"].get("Port", 40676)
if port != 5551:
    raise SystemExit("Local examples must listen on port 5551")
transport = peers[0].get("Transport", {})
if transport and set(transport) != {"Udp"}:
    raise SystemExit("Local examples must use UDP peers")
if transport.get("Udp", {}).get("Endpoint") is not None:
    pattern = r'(^\[Peer\.Transport\.Udp\][^\n]*\n)(.*?)(?=^\[|\Z)'
    def endpoint(match):
        body = re.sub(r'^\s*Endpoint\s*=.*\n?', '', match[2], flags=re.MULTILINE)
        return match[1] + f'Endpoint = "{remote}:{port}"\n' + body
    text, count = re.subn(pattern, endpoint, text, flags=re.MULTILINE | re.DOTALL)
    if count != 1:
        raise SystemExit("Could not locate the UDP peer table")
tomllib.loads(text)
pathlib.Path(destination).write_text(text)
PY

printf 'Running ex%s in %s. Ctrl+C stops this peer.\n' "$peer" "$namespace"
"${root[@]}" ip netns exec "$namespace" "$repo/target/release/covert" -vv run "$workdir/ex$peer.toml"
