/* Run after `just lib`:
 * cc -std=c11 -Wall -Wextra -Werror -Iinclude tests/ffi_smoke.c \
 *   -Ltarget/release -lcovert -Wl,-rpath,"$PWD/target/release" -o /tmp/covert-ffi-smoke
 * /tmp/covert-ffi-smoke
 */
#include "covert.h"
#include <assert.h>
#include <string.h>
#define OK(call) assert((call) == COVERT_OK)

static void transfer(CovertTunnel *from, CovertTunnel *to) {
    CovertBuffer wire = {0};
    int32_t status;
    while ((status = covert_tunnel_read_outbound(from, &wire)) == COVERT_OK) {
        OK(covert_tunnel_write_incoming(to, wire.data, wire.len));
        OK(covert_buffer_free(&wire));
    }
    assert(status == COVERT_EMPTY);
    OK(covert_tunnel_process(to, 1));
}

int main(void) {
    uint8_t ask[32], apk[32], bsk[32], bpk[32], pk[32], shared[32] = {7};
    uint64_t timestamp = 0, counter = 0;
    uint32_t kind = 99, index = 0;
    uint8_t flags = 0;
    const uint8_t message[] = "hello from C";
    CovertPacket *init = NULL, *reply = NULL, *data = NULL, *parsed = NULL;
    CovertCipher *a = NULL, *b = NULL;
    CovertLayout *layout = NULL;
    CovertBuffer encrypted = {0}, plain = {0}, wire = {0}, copy = {0};
    size_t consumed = 99;

    OK(covert_crypto_keypair(ask, apk));
    OK(covert_crypto_keypair(bsk, bpk));
    OK(covert_crypto_public_key(ask, pk));
    assert(memcmp(pk, apk, 32) == 0);
    assert(covert_crypto_public_key(NULL, pk) == COVERT_INVALID);
    OK(covert_crypto_initiate(ask, bpk, 1234, 42, &init));
    OK(covert_crypto_pre_reply(bsk, init, pk, &timestamp));
    assert(timestamp == 1234 && memcmp(pk, apk, 32) == 0);
    OK(covert_crypto_post_reply(apk, shared, 17, init, &reply, &b));
    OK(covert_crypto_finish(ask, shared, init, reply, &a));
    OK(covert_crypto_encrypt(a, message, sizeof(message), &counter, &encrypted));
    encrypted.data[0] ^= 1;
    assert(covert_crypto_decrypt(b, counter, encrypted.data, encrypted.len, &plain) == COVERT_FAILED);
    encrypted.data[0] ^= 1;
    OK(covert_crypto_decrypt(b, counter, encrypted.data, encrypted.len, &plain));
    assert(plain.len == sizeof(message) && memcmp(plain.data, message, plain.len) == 0);
    OK(covert_buffer_free(&plain));
    /* Opposite role and empty plaintext round trip. */
    OK(covert_crypto_encrypt(b, NULL, 0, &timestamp, &copy));
    OK(covert_crypto_decrypt(a, timestamp, copy.data, copy.len, &plain));
    assert(plain.len == 0);
    OK(covert_buffer_free(&copy));
    OK(covert_buffer_free(&plain));

    OK(covert_layout_new(NULL, 0, &layout));
    OK(covert_packet_data_new(17, counter, 0, encrypted.data, encrypted.len, &data));
    OK(covert_codec_encode(layout, data, &wire));
    assert(covert_codec_parse(layout, wire.data, 1, &consumed, &parsed) == COVERT_EMPTY);
    assert(consumed == 0 && parsed == NULL);
    OK(covert_codec_parse(layout, wire.data, wire.len, &consumed, &parsed));
    assert(consumed == wire.len);
    OK(covert_packet_kind(parsed, &kind));
    assert(kind == 2);
    OK(covert_packet_data(parsed, &index, &timestamp, &flags, &copy));
    assert(index == 17 && timestamp == counter && flags == 0);
    assert(copy.len == encrypted.len && memcmp(copy.data, encrypted.data, copy.len) == 0);
    OK(covert_buffer_free(&copy));
    OK(covert_buffer_free(&wire));
    OK(covert_buffer_free(&encrypted));
    OK(covert_packet_free(parsed));
    OK(covert_packet_free(data));
    OK(covert_packet_free(init));
    OK(covert_packet_free(reply));
    OK(covert_cipher_free(a));
    OK(covert_cipher_free(b));

    CovertTunnel *ta = NULL, *tb = NULL;
    CovertLiveness live = { .timeout = 60, .max_age = 3600, .ka_delay = 20, .ka_jitter = 1 };
    OK(covert_tunnel_new(layout, ask, bpk, shared, &live, &ta));
    OK(covert_tunnel_new(layout, bsk, apk, shared, &live, &tb));
    assert(covert_tunnel_local_index(ta, &index) == COVERT_EMPTY);
    OK(covert_tunnel_push(ta, message, sizeof(message)));
    OK(covert_tunnel_initiate(ta));
    OK(covert_tunnel_process(ta, 1));
    transfer(ta, tb);
    transfer(tb, ta);
    transfer(ta, tb);
    OK(covert_tunnel_is_live(ta, &flags));
    assert(flags == 1);
    OK(covert_tunnel_is_live(tb, &flags));
    assert(flags == 1);
    OK(covert_tunnel_read_packet(tb, &plain));
    assert(plain.len == sizeof(message) && memcmp(plain.data, message, plain.len) == 0);
    OK(covert_buffer_free(&plain));
    assert(covert_tunnel_read_packet(tb, &plain) == COVERT_EMPTY);
    OK(covert_tunnel_free(ta));
    OK(covert_tunnel_free(tb));
    OK(covert_layout_free(layout));
    OK(covert_packet_free(NULL));
    OK(covert_buffer_free(&plain));
    return 0;
}
