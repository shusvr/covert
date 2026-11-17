/* Portable C ABI integration test, linked against the real libcovert.so. */
#include "covert.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define OK(call) assert((call) == COVERT_OK)
static const uint8_t packet[] = {0x45,0,0,24,0,0,0,0,64,17,0,0,10,0,0,1,10,0,0,2,1,2,3,4};
static void transfer(CovertEndpoint *from, CovertEndpoint *to) {
    CovertBuffer wire = {0}; int32_t status;
    while ((status = covert_endpoint_read_outbound(from, &wire)) == COVERT_OK) {
        int32_t accepted = covert_endpoint_out_write(to, wire.data, wire.len);
        assert(accepted == COVERT_OK || accepted == COVERT_EMPTY);
        OK(covert_buffer_free(&wire));
    }
    assert(status == COVERT_EMPTY);
}
static void clients(CovertLayout *layout, const uint8_t *ask, const uint8_t *apk,
        const uint8_t *bsk, const uint8_t *bpk, const uint8_t *shared) {
    CovertLiveness live = {0,0,10,0};
    CovertEndpoint *a = NULL, *b = NULL; CovertEndpointStatus status = {0};
    OK(covert_endpoint_client_new(layout,ask,bpk,shared,&live,COVERT_CLIENT_UDP,&a));
    OK(covert_endpoint_client_new(layout,bsk,apk,shared,&live,COVERT_CLIENT_UDP,&b));
    OK(covert_endpoint_tun_write(a,packet,sizeof(packet)));
    OK(covert_endpoint_status(a,&status));
    assert(status.sent == sizeof(packet) && status.connected == 0 && status.first_established_at == 0);
    for(int i=0;i<5;i++) {
        OK(covert_endpoint_advance(a)); OK(covert_endpoint_advance(b));
        transfer(a,b); transfer(b,a);
    }
    OK(covert_endpoint_status(a,&status)); assert(status.connected == 1 && status.first_established_at != 0);
    CovertBuffer out = {0};
    OK(covert_endpoint_tun_read(b,&out));
    assert(out.len == sizeof(packet) && memcmp(out.data,packet,out.len) == 0);
    OK(covert_buffer_free(&out));
    assert(covert_endpoint_tun_read(b,&out) == COVERT_EMPTY);
    OK(covert_endpoint_status(b,&status)); assert(status.received == sizeof(packet));
    assert(covert_endpoint_tun_write(a,NULL,0) == COVERT_INVALID);
    assert(covert_endpoint_tun_write(a,NULL,1) == COVERT_INVALID);
    assert(covert_endpoint_out_write(b,NULL,0) == COVERT_FAILED);
    OK(covert_endpoint_tun_write(a,packet,sizeof(packet)));
    OK(covert_endpoint_read_outbound(a,&out));
    out.data[out.len-1] ^= 1;
    assert(covert_endpoint_out_write(b,out.data,out.len) == COVERT_FAILED);
    out.data[out.len-1] ^= 1;
    OK(covert_endpoint_out_write(b,out.data,out.len)); OK(covert_buffer_free(&out));
    OK(covert_endpoint_tun_read(b,&out)); OK(covert_buffer_free(&out));
    OK(covert_endpoint_tun_write(b,packet,sizeof(packet))); transfer(b,a);
    OK(covert_endpoint_tun_read(a,&out)); OK(covert_buffer_free(&out));
    OK(covert_endpoint_status(a,&status)); assert(status.sent == 2*sizeof(packet) && status.received == sizeof(packet));
    uint8_t v6[44] = {0x60}; v6[5]=4; v6[6]=17; v6[7]=64; v6[23]=1; v6[39]=2;
    OK(covert_endpoint_tun_write(b,v6,sizeof(v6))); transfer(b,a);
    OK(covert_endpoint_tun_read(a,&out));
    assert(out.len == sizeof(v6) && memcmp(out.data,v6,out.len) == 0);
    OK(covert_buffer_free(&out));
    assert(covert_endpoint_tun_read(a,NULL) == COVERT_INVALID);
    assert(covert_endpoint_read_outbound(a,NULL) == COVERT_INVALID);
    assert(covert_endpoint_status(a,NULL) == COVERT_INVALID);
    OK(covert_endpoint_free(a)); OK(covert_endpoint_free(b));
}
static void echo_client(CovertLayout *layout, const uint8_t *ask, const uint8_t *apk,
        const uint8_t *bsk, const uint8_t *bpk) {
    CovertLiveness live = {28,300,10,0}; CovertEndpoint *a = NULL; CovertTunnel *b = NULL;
    CovertBuffer wire = {0}, out = {0}; CovertEndpointStatus status = {0};
    OK(covert_endpoint_client_new(layout,ask,bpk,NULL,&live,COVERT_CLIENT_ICMP_ECHO_REPLY,&a));
    OK(covert_tunnel_new(layout,bsk,apk,NULL,&live,&b));
    OK(covert_endpoint_advance(a)); OK(covert_endpoint_read_outbound(a,&wire));
    assert(covert_endpoint_out_write(a,wire.data,wire.len) != COVERT_OK); /* reflected request */
    OK(covert_endpoint_status(a,&status)); assert(!status.connected);
    OK(covert_tunnel_write_incoming(b,wire.data,wire.len)); OK(covert_buffer_free(&wire));
    OK(covert_tunnel_process(b,1)); OK(covert_tunnel_read_outbound(b,&wire));
    OK(covert_endpoint_out_write(a,wire.data,wire.len)); OK(covert_buffer_free(&wire));
    OK(covert_endpoint_status(a,&status)); assert(status.connected);
    OK(covert_endpoint_tun_write(a,packet,sizeof(packet)));
    OK(covert_endpoint_read_outbound(a,&wire));
    OK(covert_tunnel_write_incoming(b,wire.data,wire.len)); OK(covert_buffer_free(&wire));
    OK(covert_tunnel_process(b,1)); OK(covert_tunnel_read_packet(b,&out));
    assert(out.len == sizeof(packet) && memcmp(out.data,packet,out.len) == 0);
    OK(covert_buffer_free(&out)); OK(covert_endpoint_free(a)); OK(covert_tunnel_free(b));
}
int main(void) {
    assert(covert_abi_version() == COVERT_ABI_VERSION);
    uint8_t ask[32],apk[32],bsk[32],bpk[32],shared[32]={7};
    OK(covert_crypto_keypair(ask,apk)); OK(covert_crypto_keypair(bsk,bpk));
    for(int random=0;random<2;random++) {
        CovertLayout *layout=NULL;
        if(random) OK(covert_layout_random(&layout)); else OK(covert_layout_new(NULL,0,&layout));
        clients(layout,ask,apk,bsk,bpk,NULL); clients(layout,ask,apk,bsk,bpk,shared);
        echo_client(layout,ask,apk,bsk,bpk);
        CovertLiveness live={0,0,10,0}; CovertEndpoint *out=NULL;
        assert(covert_endpoint_client_new(layout,ask,bpk,NULL,&live,99,&out) == COVERT_INVALID && out == NULL);
        live.timeout=UINT64_MAX;
        assert(covert_endpoint_client_new(layout,ask,bpk,NULL,&live,0,&out) == COVERT_INVALID && out == NULL);
        live.timeout=0;
        assert(covert_endpoint_client_new(layout,NULL,bpk,NULL,&live,0,&out) == COVERT_INVALID);
        assert(covert_endpoint_client_new(layout,ask,bpk,NULL,NULL,0,&out) == COVERT_INVALID);
        assert(covert_endpoint_client_new(layout,ask,bpk,NULL,&live,0,NULL) == COVERT_INVALID);
        OK(covert_layout_free(layout));
    }
    assert(covert_endpoint_advance(NULL) == COVERT_INVALID);
    assert(covert_endpoint_status(NULL,NULL) == COVERT_INVALID);
    OK(covert_endpoint_free(NULL));
    puts("Endpoint C ABI passed: queued IP, both handshake roles, PSK/layouts, rejection, statistics, ICMP client, ownership.");
}
