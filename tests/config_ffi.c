/* The opaque C handle edits the main Config and initializes the shared engine. */
#include "covert.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define OK(call) assert((call)==COVERT_OK)
#define IFACE COVERT_CONFIG_INTERFACE
static void set(CovertConfig *c,size_t scope,uint32_t field,const char *value) {
    OK(covert_config_set_string(c,scope,field,(const uint8_t *)value,strlen(value)));
}
static void expect(CovertConfig *c,size_t scope,uint32_t field,const char *value) {
    CovertBuffer out={0}; OK(covert_config_get_string(c,scope,field,&out));
    assert(out.len==strlen(value)&&memcmp(out.data,value,out.len)==0); OK(covert_buffer_free(&out));
}
static void b64(const uint8_t in[32],char out[45]) {
    const char *alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j=0;
    for(size_t i=0;i<32;i+=3) {
        uint32_t word=(uint32_t)in[i]<<16;
        if(i+1<32) word|=(uint32_t)in[i+1]<<8;
        if(i+2<32) word|=in[i+2];
        out[j++]=alphabet[(word>>18)&63];out[j++]=alphabet[(word>>12)&63];
        out[j++]=i+1<32?alphabet[(word>>6)&63]:'=';out[j++]=i+2<32?alphabet[word&63]:'=';
    }
    out[j]='\0';
}
static CovertConfig *configured(uint8_t secret,uint8_t remote) {
    CovertConfig *c=NULL;size_t peer=99;uint8_t sk[32],rsk[32],pk[32];char text[45];
    memset(sk,secret,32);memset(rsk,remote,32);OK(covert_crypto_public_key(rsk,pk));
    OK(covert_config_new(&c)); b64(sk,text);set(c,IFACE,COVERT_CONFIG_PRIVATE_KEY,text);
    b64(pk,text);OK(covert_config_add_peer(c,&peer));assert(peer==0);set(c,peer,COVERT_CONFIG_PUBLIC_KEY,text);
    set(c,IFACE,COVERT_CONFIG_ADDRESSES,"10.0.0.1/32,2001:db8::1/128");
    set(c,peer,COVERT_CONFIG_ALLOWED_IPS,"0.0.0.0/0 ::/0");
    OK(covert_config_set_u32(c,IFACE,COVERT_CONFIG_MTU,1400));return c;
}
static void transfer(CovertEndpoint *a,CovertEndpoint *b) {
    CovertBuffer out={0};int status;
    while((status=covert_endpoint_read_outbound(a,&out))==COVERT_OK) {
        status=covert_endpoint_out_write(b,out.data,out.len); assert(status==COVERT_OK||status==COVERT_EMPTY);
        OK(covert_buffer_free(&out));
    }
    assert(status==COVERT_EMPTY);
}
int main(void) {
    CovertConfig *c=NULL;size_t count=99,index=99;uint32_t number=99;CovertBuffer out={0},error={0};
    OK(covert_config_new(&c));OK(covert_config_peer_count(c,&count));assert(count==0);
    OK(covert_config_get_u32(c,IFACE,COVERT_CONFIG_MTU,&number));assert(number==1450);
    assert(covert_config_set_u32(c,IFACE,COVERT_CONFIG_MTU,65536)==COVERT_INVALID);
    assert(covert_config_set_u32(c,IFACE,COVERT_CONFIG_MTU,0)==COVERT_INVALID);
    OK(covert_config_get_u32(c,IFACE,COVERT_CONFIG_MTU,&number));assert(number==1450);
    set(c,IFACE,COVERT_CONFIG_ADDRESSES,"10.0.0.9/24, 2001:db8::1 192.0.2.1");
    expect(c,IFACE,COVERT_CONFIG_ADDRESSES,"10.0.0.9/24,2001:db8::1/128,192.0.2.1/32");
    const char *invalid="10.0.0.1/33";
    assert(covert_config_set_string(c,IFACE,COVERT_CONFIG_ADDRESSES,(const uint8_t *)invalid,strlen(invalid))==COVERT_INVALID);
    expect(c,IFACE,COVERT_CONFIG_ADDRESSES,"10.0.0.9/24,2001:db8::1/128,192.0.2.1/32");
    const uint8_t bad_utf8[]={255};assert(covert_config_set_string(c,IFACE,COVERT_CONFIG_DEV_NAME,bad_utf8,1)==COVERT_INVALID);
    set(c,IFACE,COVERT_CONFIG_DEV_NAME," co1 ");expect(c,IFACE,COVERT_CONFIG_DEV_NAME,"co1");
    OK(covert_config_get_string(c,IFACE,COVERT_CONFIG_LAYOUT,&out));
    invalid="unknown=1";assert(covert_config_set_string(c,IFACE,COVERT_CONFIG_LAYOUT,(const uint8_t *)invalid,strlen(invalid))==COVERT_INVALID);
    CovertBuffer same={0};OK(covert_config_get_string(c,IFACE,COVERT_CONFIG_LAYOUT,&same));assert(out.len==same.len&&memcmp(out.data,same.data,out.len)==0);
    OK(covert_buffer_free(&out));OK(covert_buffer_free(&same));
    assert(covert_config_get_u32(c,IFACE,COVERT_CONFIG_TIMEOUT,&number)==COVERT_EMPTY);
    OK(covert_config_set_u32(c,IFACE,COVERT_CONFIG_TIMEOUT,0));OK(covert_config_get_u32(c,IFACE,COVERT_CONFIG_TIMEOUT,&number));assert(number==0);
    OK(covert_config_clear_u32(c,IFACE,COVERT_CONFIG_TIMEOUT));assert(covert_config_get_u32(c,IFACE,COVERT_CONFIG_TIMEOUT,&number)==COVERT_EMPTY);
    OK(covert_config_add_peer(c,&index));assert(index==0);OK(covert_config_add_peer(c,&index));assert(index==1);
    OK(covert_config_set_u32(c,0,COVERT_CONFIG_KEEPALIVE,4));assert(covert_config_get_u32(c,1,COVERT_CONFIG_KEEPALIVE,&number)==COVERT_EMPTY);
    assert(covert_config_get_u32(c,2,COVERT_CONFIG_KEEPALIVE,&number)==COVERT_INVALID);
    set(c,0,COVERT_CONFIG_ENDPOINT,"[::1]:40676");expect(c,0,COVERT_CONFIG_ENDPOINT,"[::1]:40676");
    set(c,1,COVERT_CONFIG_ALLOWED_IPS,"192.0.2.0/24");
    OK(covert_config_remove_peer(c,0));expect(c,0,COVERT_CONFIG_ALLOWED_IPS,"192.0.2.0/24");
    assert(covert_config_remove_peer(c,1)==COVERT_INVALID);
    OK(covert_config_set_u32(c,IFACE,COVERT_CONFIG_LISTEN_PORT,65535));
    assert(covert_config_set_u32(c,IFACE,COVERT_CONFIG_LISTEN_PORT,65536)==COVERT_INVALID);
    OK(covert_config_get_u32(c,IFACE,COVERT_CONFIG_LISTEN_PORT,&number));assert(number==65535);
    OK(covert_config_set_u32(c,IFACE,COVERT_CONFIG_TRANSPORT,1));
    assert(covert_config_get_u32(c,IFACE,COVERT_CONFIG_LISTEN_PORT,&number)==COVERT_INVALID);
    OK(covert_config_set_u32(c,IFACE,COVERT_CONFIG_ICMP_MODE,1));OK(covert_config_get_u32(c,IFACE,COVERT_CONFIG_ICMP_MODE,&number));assert(number==1);
    assert(covert_config_set_u32(c,IFACE,COVERT_CONFIG_TRANSPORT,99)==COVERT_INVALID);
    OK(covert_config_get_u32(c,IFACE,COVERT_CONFIG_TRANSPORT,&number));assert(number==1);
    OK(covert_config_set_u32(c,0,COVERT_CONFIG_TRANSPORT,1));set(c,0,COVERT_CONFIG_ENDPOINT,"192.0.2.1");expect(c,0,COVERT_CONFIG_ENDPOINT,"192.0.2.1");
    set(c,0,COVERT_CONFIG_ENDPOINT,"");assert(covert_config_get_string(c,0,COVERT_CONFIG_ENDPOINT,&out)==COVERT_EMPTY);
    assert(covert_config_get_string(c,0,COVERT_CONFIG_PSK,&out)==COVERT_EMPTY);
    OK(covert_config_validate(c,&error));OK(covert_config_free(c));

    CovertConfig *a=configured(1,2),*b=configured(2,1);
    OK(covert_config_get_string(a,IFACE,COVERT_CONFIG_PRIVATE_KEY,&out));
    invalid="invalid secret";assert(covert_config_set_string(a,IFACE,COVERT_CONFIG_PRIVATE_KEY,(const uint8_t *)invalid,strlen(invalid))==COVERT_INVALID);
    OK(covert_config_get_string(a,IFACE,COVERT_CONFIG_PRIVATE_KEY,&same));assert(out.len==same.len&&memcmp(out.data,same.data,out.len)==0);
    OK(covert_buffer_free(&out));OK(covert_buffer_free(&same));
    OK(covert_config_public_key(a,&out));OK(covert_config_get_string(b,0,COVERT_CONFIG_PUBLIC_KEY,&same));assert(out.len==same.len&&memcmp(out.data,same.data,out.len)==0);
    OK(covert_buffer_free(&out));OK(covert_buffer_free(&same));
    CovertEndpoint *ea=NULL,*eb=NULL;OK(covert_endpoint_from_config(a,&ea,&error));OK(covert_endpoint_from_config(b,&eb,&error));
    // Endpoint owns its config clone; editing/freeing the source cannot affect it.
    set(a,0,COVERT_CONFIG_ALLOWED_IPS,"192.0.2.0/24");OK(covert_config_free(a));OK(covert_config_free(b));
    for(int i=0;i<5;i++){OK(covert_endpoint_advance(ea));OK(covert_endpoint_advance(eb));transfer(ea,eb);transfer(eb,ea);}
    const uint8_t packet[]={0x45,0,0,24,0,0,0,0,64,17,0,0,10,0,0,1,10,0,0,2,1,2,3,4};
    OK(covert_endpoint_tun_write(ea,packet,sizeof(packet)));transfer(ea,eb);OK(covert_endpoint_tun_read(eb,&out));assert(out.len==sizeof(packet)&&memcmp(out.data,packet,out.len)==0);
    OK(covert_buffer_free(&out));OK(covert_endpoint_free(ea));OK(covert_endpoint_free(eb));
    OK(covert_config_new(&c));assert(covert_endpoint_from_config(c,&ea,&error)==COVERT_INVALID&&ea==NULL);assert(error.len);OK(covert_buffer_free(&error));OK(covert_config_free(c));
    assert(covert_config_new(NULL)==COVERT_INVALID);assert(covert_config_peer_count(NULL,&count)==COVERT_INVALID);OK(covert_config_free(NULL));
    puts("Main Config C ABI passed: getters/setters, peers, liveness inheritance, validation, atomic failure, endpoint ownership and IP traffic.");
}
