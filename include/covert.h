#ifndef COVERT_H
#define COVERT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* All functions return a status. EMPTY means incomplete codec input, an empty
 * queue, or an unavailable index. FAILED includes authentication/codec errors.
 * PANIC means a Rust panic was caught; discard affected state after this status.
 * Invalid/dangling pointers, allocation failure and aborts cannot be caught.
 */
enum { COVERT_OK = 0, COVERT_EMPTY = 1, COVERT_INVALID = -1,
       COVERT_FAILED = -2, COVERT_PANIC = -3 };
typedef struct CovertLayout CovertLayout;
typedef struct CovertPacket CovertPacket;
typedef struct CovertCipher CovertCipher;
typedef struct CovertTunnel CovertTunnel;
typedef struct CovertEndpoint CovertEndpoint;
typedef struct CovertConfig CovertConfig;
#define COVERT_ABI_VERSION 2u
uint32_t covert_abi_version(void);
/* Installs Android logcat tracing; no-op on other platforms. */
void covert_android_init_logging(void);
typedef struct { uint8_t *data; size_t len; } CovertBuffer;
/* timeout/max_age are seconds (0 disables); keepalive delay/jitter are seconds. */
typedef struct {
    uint64_t timeout, max_age;
    uint32_t ka_delay, ka_jitter;
} CovertLiveness;

/* Ownership and safety:
 * - Keys are exactly 32 bytes. Optional shared keys may be NULL.
 * - Input bytes are borrowed for the call; NULL is allowed only with len == 0.
 * - Handles must come from this API. Serialize calls using the same handle.
 * - Output slots must be writable, disjoint from all inputs/other outputs, and
 *   must not contain an unfreed handle or buffer. Initialize buffers to {0}.
 * - Buffers are owned by Rust, not NUL terminated, and must be released with
 *   covert_buffer_free, which clears the buffer. Do not modify pointer/length.
 * - Free handles exactly once; NULL handle frees are allowed.
 * - Except where explicitly stated, outputs are only valid on COVERT_OK.
 * - Packet inputs are borrowed, including encode/process_packet/handshakes.
 * - Process tunnel work after writes/push/initiate, then drain outbound and
 *   plaintext queues until COVERT_EMPTY. Call process periodically for timers.
 */
int32_t covert_buffer_free(CovertBuffer *buffer);
int32_t covert_layout_free(CovertLayout *layout);
int32_t covert_packet_free(CovertPacket *packet);
int32_t covert_cipher_free(CovertCipher *cipher);
int32_t covert_tunnel_free(CovertTunnel *tunnel);

int32_t covert_crypto_keypair(uint8_t *secret, uint8_t *public_key);
int32_t covert_crypto_public_key(const uint8_t *secret, uint8_t *public_key);
int32_t covert_crypto_initiate(const uint8_t *secret, const uint8_t *public_key,
    uint64_t timestamp, uint32_t index, CovertPacket **out);
int32_t covert_crypto_pre_reply(const uint8_t *secret, const CovertPacket *initiation,
    uint8_t *public_key, uint64_t *timestamp);
int32_t covert_crypto_post_reply(const uint8_t *public_key, const uint8_t *shared,
    uint32_t index, const CovertPacket *initiation, CovertPacket **reply,
    CovertCipher **cipher);
int32_t covert_crypto_finish(const uint8_t *secret, const uint8_t *shared,
    const CovertPacket *initiation, const CovertPacket *reply, CovertCipher **out);
int32_t covert_crypto_encrypt(const CovertCipher *cipher, const uint8_t *data,
    size_t len, uint64_t *counter, CovertBuffer *out);
int32_t covert_crypto_decrypt(const CovertCipher *cipher, uint64_t counter,
    const uint8_t *data, size_t len, CovertBuffer *out);

/* Empty text selects the default layout; otherwise use the Rust layout syntax
 * (for example "m=0&odp=1400"). Layouts are validated on creation. */
int32_t covert_layout_new(const uint8_t *text, size_t len, CovertLayout **out);
int32_t covert_layout_random(CovertLayout **out);
int32_t covert_layout_string(const CovertLayout *layout, CovertBuffer *out);
/* Parses one packet; on EMPTY, *out is NULL and *consumed is zero. */
int32_t covert_codec_parse(const CovertLayout *layout, const uint8_t *data,
    size_t len, size_t *consumed, CovertPacket **out);
int32_t covert_codec_encode(const CovertLayout *layout, const CovertPacket *packet,
    CovertBuffer *out);
/* Data flags: 0 = normal, 1 = junk/keepalive. */
int32_t covert_packet_data_new(uint32_t index, uint64_t counter, uint8_t flags,
    const uint8_t *data, size_t len, CovertPacket **out);
/* Kind: 0 = initiation, 1 = reply, 2 = data. */
int32_t covert_packet_kind(const CovertPacket *packet, uint32_t *kind);
/* Returns a copy of the ciphertext; requires a data packet. */
int32_t covert_packet_data(const CovertPacket *packet, uint32_t *index,
    uint64_t *counter, uint8_t *flags, CovertBuffer *out);

int32_t covert_tunnel_new(const CovertLayout *layout, const uint8_t *secret,
    const uint8_t *public_key, const uint8_t *shared, const CovertLiveness *liveness,
    CovertTunnel **out);
int32_t covert_tunnel_initiate(CovertTunnel *tunnel);
/* flush_on_error is 0 or 1; errors are reported even when input is cleared. */
int32_t covert_tunnel_process(CovertTunnel *tunnel, uint8_t flush_on_error);
int32_t covert_tunnel_push(CovertTunnel *tunnel, const uint8_t *data, size_t len);
/* Buffered byte-stream input; use process_packet for already decoded packets. */
int32_t covert_tunnel_write_incoming(CovertTunnel *tunnel, const uint8_t *data, size_t len);
int32_t covert_tunnel_process_packet(CovertTunnel *tunnel, const CovertPacket *packet);
int32_t covert_tunnel_read_outbound(CovertTunnel *tunnel, CovertBuffer *out);
int32_t covert_tunnel_read_outbound_packet(CovertTunnel *tunnel, CovertPacket **out);
int32_t covert_tunnel_read_packet(CovertTunnel *tunnel, CovertBuffer *out);
int32_t covert_tunnel_is_live(const CovertTunnel *tunnel, uint8_t *out);
int32_t covert_tunnel_local_index(const CovertTunnel *tunnel, uint32_t *out);
/* Opaque handle to the library's main Config, not an Android/client DTO.
 * New configs have no peers, default layout, MTU 1450 and UDP listener 40676.
 * COVERT_CONFIG_INTERFACE selects interface fields; other scopes are peer
 * indices. Removing a peer shifts subsequent indices. Getters copy their output.
 * Strings are UTF-8. Keys use Base64; IP ranges use comma/whitespace-separated
 * numeric CIDRs (bare IPs imply /32 or /128). Empty PSK clears it; empty endpoint
 * selects passive/unspecified transport. Endpoints must already be resolved:
 * UDP and QUIC-shaped UDP use IP:port ([IPv6]:port). ICMP uses IPv4. Unknown
 * scope/field combinations return INVALID. Invalid setters leave the config unchanged.
 * TRANSPORT is UDP=0, ICMP=1, or QUIC-shaped UDP=3. Peers also support
 * unspecified=2. ICMP_MODE is EchoReply=0/OnlyEcho=1. Changing transport initializes its transport defaults;
 * configure its port/mode/endpoint afterward. Interface changes do not rewrite
 * peer transports. Optional PSK/endpoint/liveness getters return EMPTY if unset.
 * Liveness u32 fields are optional; clear restores the normal fallback rules.
 * Key getters return secret material when requested; never log it.
 * The optional error buffer must start at {0}; INVALID may populate it with a
 * diagnostic, which must be freed even when the operation fails.
 */
#define COVERT_CONFIG_INTERFACE SIZE_MAX
enum { COVERT_CONFIG_LAYOUT = 0, COVERT_CONFIG_DEV_NAME = 1,
    COVERT_CONFIG_PRIVATE_KEY = 2, COVERT_CONFIG_ADDRESSES = 3,
    COVERT_CONFIG_PUBLIC_KEY = 4, COVERT_CONFIG_PSK = 5,
    COVERT_CONFIG_ALLOWED_IPS = 6, COVERT_CONFIG_ENDPOINT = 7,
    COVERT_CONFIG_PEER_ID = 8, COVERT_CONFIG_MTU = 16,
    COVERT_CONFIG_TRANSPORT = 17, COVERT_CONFIG_LISTEN_PORT = 18,
    COVERT_CONFIG_ICMP_MODE = 19, COVERT_CONFIG_TIMEOUT = 20,
    COVERT_CONFIG_MAX_AGE = 21, COVERT_CONFIG_KEEPALIVE = 22,
    COVERT_CONFIG_KEEPALIVE_JITTER = 23 };
int32_t covert_config_new(CovertConfig **out);
/* UTF-8 query (without URL prefix); *out is null on failure. Free with covert_config_free. */
int32_t covert_config_from_query(const uint8_t *data, size_t len, CovertConfig **out);
/* UTF-8 JSON output, including private keys. Release with covert_buffer_free. */
int32_t covert_config_to_json(const CovertConfig *config, CovertBuffer *out);
int32_t covert_config_free(CovertConfig *config);
int32_t covert_config_add_peer(CovertConfig *config, size_t *index);
int32_t covert_config_remove_peer(CovertConfig *config, size_t index);
int32_t covert_config_peer_count(const CovertConfig *config, size_t *count);
int32_t covert_config_set_string(CovertConfig *config, size_t scope, uint32_t field, const uint8_t *data, size_t len);
int32_t covert_config_get_string(const CovertConfig *config, size_t scope, uint32_t field, CovertBuffer *out);
int32_t covert_config_set_u32(CovertConfig *config, size_t scope, uint32_t field, uint32_t value);
int32_t covert_config_get_u32(const CovertConfig *config, size_t scope, uint32_t field, uint32_t *out);
int32_t covert_config_clear_u32(CovertConfig *config, size_t scope, uint32_t field);
int32_t covert_config_validate(const CovertConfig *config, CovertBuffer *error);
/* Derives the interface public key as Base64 text, without a trailing NUL. */
int32_t covert_config_public_key(const CovertConfig *config, CovertBuffer *out);
/* Copies the main Config into a fixed-remote client endpoint. Exactly one peer
 * and UDP, QUIC-shaped UDP, or ICMP EchoReply are required. The config can then
 * be edited or freed. */
int32_t covert_endpoint_from_config(const CovertConfig *config, CovertEndpoint **out, CovertBuffer *error);

/* Fixed-remote single-peer client API, backed by the shared Endpoint engine.
 * The host owns/protects/binds the socket and handles UDP or ICMP framing.
 * Both IPv4 and IPv6 IP packets are accepted; select routes in the host VPN.
 * UDP and QUIC_SHAPED_UDP support either handshake role. Send and receive their
 * encoded datagrams as UDP payloads. ICMP_ECHO_REPLY only initiates and
 * rejects reflected initiations. ICMP inputs must already be unwrapped replies.
 * Advance once after creation and periodically (e.g. every 100ms). Writes drive
 * immediate work too. Drain both output queues until COVERT_EMPTY each tick.
 * out_write requires exactly one complete encoded datagram; OK means accepted,
 * EMPTY means ignored, FAILED means malformed or unauthenticated. Neither EMPTY
 * nor FAILED from network input is fatal. PANIC requires discarding the handle.
 * Layout and keys are copied. Liveness timeout/max_age must fit uint32_t.
 * Statistics count accepted plaintext, including queued pre-handshake traffic;
 * receive bytes are counted when drained by tun_read. Timestamps are Unix ms,
 * with zero meaning never established. connected is 0 or 1.
 */
enum { COVERT_CLIENT_UDP = 0, COVERT_CLIENT_ICMP_ECHO_REPLY = 1,
    COVERT_CLIENT_QUIC_SHAPED_UDP = 2 };
typedef struct {
    uint64_t sent, received, first_established_at, last_established_at;
    uint8_t connected;
} CovertEndpointStatus;
int32_t covert_endpoint_client_new(const CovertLayout *layout,
    const uint8_t *secret, const uint8_t *public_key, const uint8_t *shared,
    const CovertLiveness *liveness, uint32_t mode, CovertEndpoint **out);
int32_t covert_endpoint_free(CovertEndpoint *endpoint);
int32_t covert_endpoint_advance(CovertEndpoint *endpoint);
int32_t covert_endpoint_tun_write(CovertEndpoint *endpoint, const uint8_t *data, size_t len);
int32_t covert_endpoint_out_write(CovertEndpoint *endpoint, const uint8_t *data, size_t len);
int32_t covert_endpoint_read_outbound(CovertEndpoint *endpoint, CovertBuffer *out);
int32_t covert_endpoint_tun_read(CovertEndpoint *endpoint, CovertBuffer *out);
int32_t covert_endpoint_status(const CovertEndpoint *endpoint, CovertEndpointStatus *out);
#ifdef __cplusplus
}
#endif
#endif
