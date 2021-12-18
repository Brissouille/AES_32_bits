#ifndef AES_H
#define AES_H

#include <stdlib.h>

void encrypt(u_int32_t* key, int keylength, u_int32_t* msg, u_int32_t* cipher);
void decrypt(u_int32_t* key, u_int32_t* msg, u_int32_t* cipher);
void print_state(u_int32_t* state);

// if we use the precomputed tbox
#if defined(TBOX)
    #define Tbox0(x) Tbox0[x]
    #define Tbox1(x) Tbox1[x]
    #define Tbox2(x) Tbox2[x]
    #define Tbox3(x) Tbox3[x]
// else we compute the Tbox on the fly
#else
    // Multiplication in Gallois Field (x^8+x^4+x^3+x+1)
    #define mult2(x) ((x<<1)%256) ^ (0x1b * ((x>>7) & 1))
    #define mult3(x) ((mult2(x)) ^ x)
    
    // Tbox with 8 bits in input and 32 bits in output
    #define Tbox0(x) ((mult2(Sbox[x])) << 24) ^ ((Sbox[x]) << 16) ^ ((Sbox[x]) << 8) ^ (mult3((Sbox[x])))
    #define Tbox1(x) ((mult3(Sbox[x])) << 24) ^ ((mult2(Sbox[(x)])) << 16) ^ ((Sbox[(x)]) << 8) ^ (Sbox[x])
    #define Tbox2(x) ((Sbox[x]) << 24) ^ ((mult3(Sbox[x])) << 16) ^ ((mult2(Sbox[x])) << 8) ^ (Sbox[x])
    #define Tbox3(x) ((Sbox[x]) << 24) ^ ((Sbox[x]) << 16) ^ ((mult3(Sbox[x])) << 8) ^ (mult2(Sbox[x]))
#endif

// Tbox4 with 32 bits in input and 32 bits in output
#define Tbox4(x) ((Sbox[(x & 0xff000000) >> 24]) << 24) ^ ((Sbox[(x & 0x00ff0000) >> 16]) << 16) ^ ((Sbox[(x & 0x0000ff00) >> 8]) << 8) ^ ((Sbox[(x & 0x000000ff)]))

#define SHIFT_ROW(x, i) (x[i] & 0xff000000) ^ (x[(i+1)%4] & 0x00ff0000) ^ (x[(i+2)%4] & 0x0000ff00) ^ (x[((i+3)%4)] & 0x000000ff);
#define ROT_WORD(x) (((x & 0xff000000)>>24) ^ (x <<8))

// Little endian convention ex : BYTE("0xb0b1b2b3", 0) = b0
#define BYTE(x, n) ((x & (0xff << (8*(3-n)))) >> (8*(3-n)))

#endif
