#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>

int main () {

    unsigned char * key = (unsigned char *) "\xfd\x28\xb3\x4c\x2c\x26\x1d\x1d";
    //unsigned char * data = (unsigned char *) "\xfd\x28\xb3\x4c\x2c\x26\x1d\x1d";
    //unsigned char * key = (unsigned char *) "\x20\xdc\x4b\xdd\xa9\x78\x84\xc5";
    unsigned char * data = (unsigned char *) "\x20\xdc\x4b\xdd\xa9\x78\x84\xc5";
    //unsigned char * key = (unsigned char *) "\xc5\x84\x78\xa9\xdd\x4b\xdc\x20";
    //unsigned char * data = (unsigned char *) "\x1d\x1d\x26\x2c\x4c\xb3\x28\xfd";
    unsigned char * result;

    HMAC_CTX * ctx;
    ENGINE * engine;

    //ENGINE_load_builtin_engines();
    //ENGINE_register_all_complete();
    //ENGINE_set_default_digests(engine);

    //HMAC_CTX_init(ctx);
    //HMAC_Init_ex(ctx, key, 16, EVP_sha1(), engine);
    result = HMAC(EVP_sha1(), key, 8, data, 8, NULL, NULL);
    int i = 0;
    uint32_t num32 = *((uint32_t *)(result + 0));
    uint32_t num32Rev = *((uint32_t *)(result + 16));
    /*uint32_t result32 = be64toh(num64Dup) >> 32;
    unsigned char * res32Print = (unsigned char *) &result32;

    printf (" %u \n ", &result32);
    for (i=0; i < 4; i++) {
        printf("%x",res32Print[i]);
    }*/
    printf (" %u %u \n",num32, num32Rev); 
    printf("\n");
    for (i=0; i < 20; i++) {
        printf("%x",result[i]);
    }
    printf("\n");

}

