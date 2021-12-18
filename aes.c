#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "aes.h"

#ifdef TBOX
  #include "tbox.c"
#endif

static void expand_key(u_int32_t* key, int keylength, u_int32_t (*expkey)[4]);

static void addRoundKey(u_int32_t* expkey, u_int32_t* key);

static void shiftRow(u_int32_t* state);

static void subByte_MixColumn(u_int32_t* state);

static void subByte(u_int32_t* state);

static void print_tbox(void);

u_int32_t rcon[28] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 
                      0x10000000, 0x20000000, 0x40000000, 0x80000000, 
                      0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 
                      0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000, 
                      0x5E000000, 0xBC000000, 0x63000000, 0xC6000000, 
                      0x97000000, 0x35000000, 0x6A000000, 0xD4000000, 
                      0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000};

u_int8_t Sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

#pragma GCC optimize("O0")
void encrypt(u_int32_t* key, int keylength, u_int32_t* msg, u_int32_t* cipher) {
    u_int32_t expkey[17][4];
    u_int32_t state[4];
    u_int8_t Nr, Nk;
    
    Nk = keylength / 32;
    Nr = 10 + (Nk - 4);
    memcpy(state, msg, 4 * sizeof(u_int32_t));
    
    expand_key(key, keylength, expkey);

#ifdef COUNTER_MEASURES 
    mask = masking_key(expkey);
    mask_tbox = masking_tbox(mask);
#endif
    addRoundKey(state, expkey[0]);
    
    for(int i=0; i<(Nr-1); i++) {
        shiftRow(state);
        subByte_MixColumn(state);
        addRoundKey(state, expkey[i+1]);
    }
   
    // Last Round 
    shiftRow(state);
    subByte(state);
    addRoundKey(state, expkey[Nr]);
    
    memcpy(cipher, state, 4 * sizeof(u_int32_t));
}

void decrypt(u_int32_t* key, u_int32_t* msg, u_int32_t* cipher) {
}

static void expand_key(u_int32_t* key, int keylength, u_int32_t(*expkey)[4]) {

    u_int32_t expkey_tmp[4*17];
    u_int8_t Nr, Nk;
    
    Nk = keylength / 32;
    Nr = 10 + (Nk - 4);

    for(int i=0; i<4*(Nr+1); i++) {
        if(i<Nk){
            expkey_tmp[i] = key[i];
        } else if((i >= Nk) && ((i%Nk) == 0)) {
            expkey_tmp[i] = Tbox4(ROT_WORD(expkey_tmp[i-1])) ^ rcon[(i/Nk)-1] ^ expkey_tmp[i-Nk];
        // Special case for AES 256
        } else if((i >= Nk) && (Nk > 6) && ((i%Nk) == 4)) {
            expkey_tmp[i] = Tbox4(expkey_tmp[i-1]) ^ expkey_tmp[i-Nk];
        } else {
            expkey_tmp[i] = expkey_tmp[i-1] ^ expkey_tmp[i-Nk];
        }
        expkey[i/4][i%4] = expkey_tmp[i];
    }
}

static void addRoundKey(u_int32_t* state, u_int32_t* key) {
    for(int i=0; i<4; i++) {
        state[i] ^= key[i];
    } 
}

static void shiftRow(u_int32_t* state) {
    u_int32_t tmp[4];

    memcpy(tmp, state, 4 * sizeof(u_int32_t));

    for(int i=0; i<4; i++) {
        state[i] = SHIFT_ROW(tmp, i);
    }
}

static void subByte_MixColumn(u_int32_t* state) {
    // Tbox0...Tbox3 use 8 bits for input and 32 for output
    state[0] = Tbox0(BYTE(state[0], 0)) ^ Tbox1(BYTE(state[0], 1)) ^ Tbox2(BYTE(state[0], 2)) ^ Tbox3(BYTE(state[0], 3));
    state[1] = Tbox0(BYTE(state[1], 0)) ^ Tbox1(BYTE(state[1], 1)) ^ Tbox2(BYTE(state[1], 2)) ^ Tbox3(BYTE(state[1], 3));
    state[2] = Tbox0(BYTE(state[2], 0)) ^ Tbox1(BYTE(state[2], 1)) ^ Tbox2(BYTE(state[2], 2)) ^ Tbox3(BYTE(state[2], 3));
    state[3] = Tbox0(BYTE(state[3], 0)) ^ Tbox1(BYTE(state[3], 1)) ^ Tbox2(BYTE(state[3], 2)) ^ Tbox3(BYTE(state[3], 3));
}

static void subByte(u_int32_t* state) {
    // Tbox4 uses 32 bits for input and 32 for output
    state[0] = Tbox4(state[0]);
    state[1] = Tbox4(state[1]);
    state[2] = Tbox4(state[2]);
    state[3] = Tbox4(state[3]);
}

// Print the matrix 4 x u_int32_t
void print_state(u_int32_t* state) {
    for(int toto=0; toto<4; toto++) {
        printf("state[%d] = %08x\n", toto, state[toto]);
    }
}

// Print The Tbox0 Tbox1 Tbox2 Tbox3 Tbox4 
static void print_tbox(void) {
    printf("Tbox0[256] = { ");
    for(int i=0; i<256; i++) {
        printf("%08x, ", Tbox0(i));
    }
    printf("};\n");
    
    printf("Tbox1[256] = { ");
    for(int i=0; i<256; i++) {
        printf("%08x, ", Tbox1(i));
    }
    printf("};\n");
    
    printf("Tbox2[256] = { ");
    for(int i=0; i<256; i++) {
        printf("%08x, ", Tbox2(i));
    }
    printf("};\n");
    
    printf("Tbox3[256] = { ");
    for(int i=0; i<256; i++) {
        printf("%08x, ", Tbox3(i));
    }
    printf("};\n");
    
}

static void print_mult(void) {
    printf("mult2[256] = { ");  
    for(int i=0; i<256; i++) {
        printf("%02x, \n", mult2(i));
    }
    printf("};\n");
    
    printf("mult3[256] = { ");
    for(int i=0; i<256; i++) {
        printf("%02x, \n", mult3(i));
    }
    printf("};\n");
}

int main(void) {
    print_tbox();
}
