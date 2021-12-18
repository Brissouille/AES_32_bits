#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

int main(void) {

    int keylength;
    u_int32_t key_128[4];
    u_int32_t key_192[6];
    u_int32_t key_256[8];
    u_int32_t msg[4];
    u_int32_t cipher[4];

    msg[0] = 0x00112233;
    msg[1] = 0x44556677;
    msg[2] = 0x8899AABB;
    msg[3] = 0xCCDDEEFF;
    
    keylength = 128;
    key_128[0] = 0x00010203;
    key_128[1] = 0x04050607;
    key_128[2] = 0x08090a0b;
    key_128[3] = 0x0c0d0e0f;
    encrypt(key_128, keylength, msg, cipher);
    print_state(cipher);

    keylength = 192;
    key_192[0] = key_128[0];
    key_192[1] = key_128[1];
    key_192[2] = key_128[2];
    key_192[3] = key_128[3];
    key_192[4] = 0x10111213;
    key_192[5] = 0x14151617;
    printf("******************************\n");
    encrypt(key_192, keylength, msg, cipher);
    print_state(cipher);
    
    keylength = 256;
    key_256[0] = key_192[0];
    key_256[1] = key_192[1];
    key_256[2] = key_192[2];
    key_256[3] = key_192[3];
    key_256[4] = key_192[4];
    key_256[5] = key_192[5];
    key_256[6] = 0x18191a1b;
    key_256[7] = 0x1c1d1e1f;
    printf("******************************\n");
    encrypt(key_256, keylength, msg, cipher);
    
    print_state(cipher);
    return 0;
}
