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
int32_t covert_tunnel_process(CovertTunnel *tunnel);
int32_t covert_tunnel_push(CovertTunnel *tunnel, const uint8_t *data, size_t len);
/* Buffered byte-stream input; use process_packet for already decoded packets. */
int32_t covert_tunnel_write_incoming(CovertTunnel *tunnel, const uint8_t *data, size_t len);
int32_t covert_tunnel_process_packet(CovertTunnel *tunnel, const CovertPacket *packet);
int32_t covert_tunnel_read_outbound(CovertTunnel *tunnel, CovertBuffer *out);
int32_t covert_tunnel_read_outbound_packet(CovertTunnel *tunnel, CovertPacket **out);
int32_t covert_tunnel_read_packet(CovertTunnel *tunnel, CovertBuffer *out);
int32_t covert_tunnel_is_live(const CovertTunnel *tunnel, uint8_t *out);
int32_t covert_tunnel_local_index(const CovertTunnel *tunnel, uint32_t *out);
#ifdef __cplusplus
}
#endif
#endif
