#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#define MAX_BYTES 16


struct ByteArray {
    uint8_t bytes[MAX_BYTES];
    int nbytes;
};


typedef struct ByteArray ByteArray;

static ByteArray FSM[3];

static ByteArray LFSR[16];

static uint8_t SR_box[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAb, 0x76,},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,},
};

static uint8_t SQ_box[16][16] = {
    {0x25,0x24,0x73,0x67,0xD7,0xAE,0x5C,0x30,0xA4,0xEE,0x6E,0xCB,0x7D,0xB5,0x82,0xDB,},
    {0xE4,0x8E,0x48,0x49,0x4F,0x5D,0x6A,0x78,0x70,0x88,0xE8,0x5F,0x5E,0x84,0x65,0xE2,},
    {0xD8,0xE9,0xCC,0xED,0x40,0x2F,0x11,0x28,0x57,0xD2,0xAC,0xE3,0x4A,0x15,0x1B,0xB9,},
    {0xB2,0x80,0x85,0xA6,0x2E,0x02,0x47,0x29,0x07,0x4B,0x0E,0xC1,0x51,0xAA,0x89,0xD4,},
    {0xCA,0x01,0x46,0xB3,0xEF,0xDD,0x44,0x7B,0xC2,0x7F,0xBE,0xC3,0x9F,0x20,0x4C,0x64,},
    {0x83,0xA2,0x68,0x42,0x13,0xB4,0x41,0xCD,0xBA,0xC6,0xBB,0x6D,0x4D,0x71,0x21,0xF4,},
    {0x8D,0xB0,0xE5,0x93,0xFE,0x8F,0xE6,0xCF,0x43,0x45,0x31,0x22,0x37,0x36,0x96,0xFA,},
    {0xBC,0x0F,0x08,0x52,0x1D,0x55,0x1A,0xC5,0x4E,0x23,0x69,0x7A,0x92,0xFF,0x5B,0x5A,},
    {0xEB,0x9A,0x1C,0xA9,0xD1,0x7E,0x0D,0xFC,0x50,0x8A,0xB6,0x62,0xF5,0x0A,0xF8,0xDC,},
    {0x03,0x3C,0x0C,0x39,0xF1,0xB8,0xF3,0x3D,0xF2,0xD5,0x97,0x66,0x81,0x32,0xA0,0x00,},
    {0x06,0xCE,0xF6,0xEA,0xB7,0x17,0xF7,0x8C,0x79,0xD6,0xA7,0xBF,0x8B,0x3F,0x1F,0x53,},
    {0x63,0x75,0x35,0x2C,0x60,0xFD,0x27,0xD3,0x94,0xA5,0x7C,0xA1,0x05,0x58,0x2D,0xBD,},
    {0xD9,0xC7,0xAF,0x6B,0x54,0x0B,0xE0,0x38,0x04,0xC8,0x9D,0xE7,0x14,0xB1,0x87,0x9C,},
    {0xDF,0x6F,0xF9,0xDA,0x2A,0xC4,0x59,0x16,0x74,0x91,0xAB,0x26,0x61,0x76,0x34,0x2B,},
    {0xAD,0x99,0xFB,0x72,0xEC,0x33,0x12,0xDE,0x98,0x3B,0xC0,0x9B,0x3E,0x18,0x10,0x3A,},
    {0x56,0xE1,0x77,0xC9,0x1E,0x9E,0x95,0xA3,0x90,0x19,0xA8,0x6C,0x09,0xD0,0xF0,0x86,},
};


ByteArray ByteArray__from_int(uint32_t val, int nbytes) {
    ByteArray ret;
    ret.nbytes = nbytes;
    memset(ret.bytes, 0, MAX_BYTES);
    for (int i = 0; i < nbytes; i++) {
        ret.bytes[i] = val & 0xFF;
        val >>= 8;
    }
    return ret;
}


uint32_t ByteArray__to_int(ByteArray a) {
    uint32_t ret = 0;
    for (int i = 0; i < 4; i++) {
        ret += (uint32_t)(a.bytes[i]) << (i*8);
    }
    return ret;
}

ByteArray ByteArray__OR(ByteArray a, ByteArray b) {
    ByteArray ret;
    int i = 0;
    while (i < a.nbytes || i < b.nbytes) {
        ret.bytes[i] = a.bytes[i] ^ b.bytes[i];
        i++;
    }
    ret.nbytes = i;
    memset(ret.bytes + i, 0, MAX_BYTES - i);
    return ret;
}


ByteArray ByteArray__add(ByteArray a, ByteArray b) {
    if (a.nbytes != 4 || b.nbytes != 4) {
        printf("Add error\n");
    }
    return ByteArray__from_int(ByteArray__to_int(a) + ByteArray__to_int(b), 4);
}


void ByteArray__print(ByteArray a) {
    for (int i = a.nbytes - 1; i >= 0; i--) {
        printf("%02x", a.bytes[i]);
    }
}


// V: 8 bits
// c: 8 bits
// ret: 8 bits
ByteArray MULx(ByteArray V, ByteArray c) {
    if (V.nbytes != 1 || c.nbytes != 1) {
        printf("MULx error\n");
    }
    ByteArray ret = V;
    ret.bytes[0] <<= 1;
    if (V.bytes[0] & 0x80) {
        return (ByteArray__OR(ret, c));
    }
    else {
        return ret;
    } 
}


// V: 8 bits
// c: 8 bits
// ret: 8 bits
ByteArray MULy(ByteArray V, int i, ByteArray c) {
    if (V.nbytes != 1 || c.nbytes != 1) {
        printf("MULy error\n");
    }
    if (i == 0) {
        return V;
    }
    else {
        return MULx(MULy(V, i-1, c), c);
    }
}


// c: 8 bits
ByteArray MULa(ByteArray c) {
    if (c.nbytes != 1) {
        printf("MULa error\n");
    }
    ByteArray const_0xA9 = ByteArray__from_int(0xA9, 1);
    ByteArray ret = ByteArray__from_int(0x0, 4);
    ret.bytes[0] = MULy(c, 239, const_0xA9).bytes[0];
    ret.bytes[1] = MULy(c, 48, const_0xA9).bytes[0];
    ret.bytes[2] = MULy(c, 245, const_0xA9).bytes[0];
    ret.bytes[3] = MULy(c, 23, const_0xA9).bytes[0];
    return ret;
}


// c: 8 bits
ByteArray DIVa(ByteArray c) {
    if (c.nbytes != 1) {
        printf("DIVa error\n");
    }
    ByteArray const_0xA9 = ByteArray__from_int(0xA9, 1);
    ByteArray ret = ByteArray__from_int(0x0, 4);
    ret.bytes[0] = MULy(c, 64, const_0xA9).bytes[0];
    ret.bytes[1] = MULy(c, 6, const_0xA9).bytes[0];
    ret.bytes[2] = MULy(c, 39, const_0xA9).bytes[0];
    ret.bytes[3] = MULy(c, 16, const_0xA9).bytes[0];
    return ret;
}


// w: 8 bits
ByteArray SR(ByteArray w) {
    if (w.nbytes != 1) {
        printf("SR error\n");
    }
    uint8_t v = w.bytes[0];
    return ByteArray__from_int(SR_box[v >> 4][v & 0xF], 1);
}


// w: 8 bits
ByteArray SQ(ByteArray w) {
    if (w.nbytes != 1) {
        printf("SQ error\n");
    }
    uint8_t v = w.bytes[0];
    return ByteArray__from_int(SQ_box[v >> 4][v & 0xF], 1);
}


// w: 32 bits
ByteArray S1(ByteArray w) {
    if (w.nbytes != 4) {
        printf("S1 error\n");
    }
    ByteArray const_0x1B = ByteArray__from_int(0x1B, 1);

    ByteArray w0 = ByteArray__from_int(w.bytes[3], 1);
    ByteArray w1 = ByteArray__from_int(w.bytes[2], 1);
    ByteArray w2 = ByteArray__from_int(w.bytes[1], 1);
    ByteArray w3 = ByteArray__from_int(w.bytes[0], 1);
    
    ByteArray r0 = MULx(SR(w0) , const_0x1B);
    r0 = ByteArray__OR(r0, SR(w1));
    r0 = ByteArray__OR(r0, SR(w2));
    r0 = ByteArray__OR(r0, MULx(SR(w3), const_0x1B));
    r0 = ByteArray__OR(r0, SR(w3));

    ByteArray r1 = MULx(SR(w0) , const_0x1B);
    r1 = ByteArray__OR(r1, SR(w0));
    r1 = ByteArray__OR(r1, MULx(SR(w1), const_0x1B));
    r1 = ByteArray__OR(r1, SR(w2));
    r1 = ByteArray__OR(r1, SR(w3));

    ByteArray r2 = SR(w0);
    r2 = ByteArray__OR(r2, MULx(SR(w1), const_0x1B));
    r2 = ByteArray__OR(r2, SR(w1));
    r2 = ByteArray__OR(r2, MULx(SR(w2), const_0x1B));
    r2 = ByteArray__OR(r2, SR(w3));

    ByteArray r3 = SR(w0);
    r3 = ByteArray__OR(r3, SR(w1));
    r3 = ByteArray__OR(r3, MULx(SR(w2), const_0x1B));
    r3 = ByteArray__OR(r3, SR(w2));
    r3 = ByteArray__OR(r3, MULx(SR(w3), const_0x1B));

    ByteArray ret = ByteArray__from_int(0x0, 4);
    ret.bytes[0] = r3.bytes[0];
    ret.bytes[1] = r2.bytes[0];
    ret.bytes[2] = r1.bytes[0];
    ret.bytes[3] = r0.bytes[0];

    printf("s1:\n");
    ByteArray__print(w);printf("\n");
    printf("r0:\n");
    ByteArray__print(r0);printf("\n");
    printf("r1:\n");
    ByteArray__print(r1);printf("\n");
    printf("r2:\n");
    ByteArray__print(r2);printf("\n");
    printf("r3:\n");
    ByteArray__print(r3);printf("\n");
    ByteArray__print(w);printf("\ns1:\n");
    ByteArray__print(ret);
    printf("\n\n");
    
    return ret;
}



// w: 32 bits
ByteArray S2(ByteArray w) {
    
    if (w.nbytes != 4) {
        printf("S2 error\n");
    }
    ByteArray const_0x69 = ByteArray__from_int(0x69, 1);

    ByteArray w0 = ByteArray__from_int(w.bytes[3], 1);
    ByteArray w1 = ByteArray__from_int(w.bytes[2], 1);
    ByteArray w2 = ByteArray__from_int(w.bytes[1], 1);
    ByteArray w3 = ByteArray__from_int(w.bytes[0], 1);
    
    ByteArray r0 = MULx(SQ(w0) , const_0x69);
    r0 = ByteArray__OR(r0, SQ(w1));
    r0 = ByteArray__OR(r0, SQ(w2));
    r0 = ByteArray__OR(r0, MULx(SQ(w3), const_0x69));
    r0 = ByteArray__OR(r0, SQ(w3));

    ByteArray r1 = MULx(SQ(w0) , const_0x69);
    r1 = ByteArray__OR(r1, SQ(w0));
    r1 = ByteArray__OR(r1, MULx(SQ(w1), const_0x69));
    r1 = ByteArray__OR(r1, SQ(w2));
    r1 = ByteArray__OR(r1, SQ(w3));

    ByteArray r2 = SQ(w0);
    r2 = ByteArray__OR(r2, MULx(SQ(w1), const_0x69));
    r2 = ByteArray__OR(r2, SQ(w1));
    r2 = ByteArray__OR(r2, MULx(SQ(w2), const_0x69));
    r2 = ByteArray__OR(r2, SQ(w3));

    ByteArray r3 = SQ(w0);
    r3 = ByteArray__OR(r3, SQ(w1));
    r3 = ByteArray__OR(r3, MULx(SQ(w2), const_0x69));
    r3 = ByteArray__OR(r3, SQ(w2));
    r3 = ByteArray__OR(r3, MULx(SQ(w3), const_0x69));

    ByteArray ret = ByteArray__from_int(0x0, 4);
    ret.bytes[0] = r3.bytes[0];
    ret.bytes[1] = r2.bytes[0];
    ret.bytes[2] = r1.bytes[0];
    ret.bytes[3] = r0.bytes[0];
    
    printf("s2:\n");
    ByteArray__print(w);printf("s1:\n");
    ByteArray__print(ret);
    printf("\n\n");

    return ret;
}


void FSM__init() {
    for (int i = 0; i < 3; i++) {
        FSM[i] = ByteArray__from_int(0x0, 4);
        printf("\n");
        ByteArray__print(FSM[i]);
    }
    printf("\n\n");
}

// s15: 32 bits
// s5: 32 bits
ByteArray FSM__clock() {
    ByteArray F = ByteArray__add(LFSR[15], FSM[0]);
    printf("\n\nF result\n");
    ByteArray__print(F);
    printf("\n");
    F = ByteArray__OR(F, FSM[1]);
    
    ByteArray__print(F);
    printf("\n");

    ByteArray r = ByteArray__OR(FSM[2], LFSR[5]);
    printf("\n\nr result\n");
    ByteArray__print(r);
    printf("\n");
    r = ByteArray__add(r, FSM[1]);
    ByteArray__print(r);
    printf("\n");
    FSM[2] = S2(FSM[1]);
    FSM[1] = S1(FSM[0]);
    FSM[0] = r;

    return F;
}


// K: 128 bits
// IV: 128 bits
void LFSR__init(ByteArray K, ByteArray IV) {
    ByteArray const_all_one = ByteArray__from_int(0xffffffff, 4);
    ByteArray k0 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        k0.bytes[i] = K.bytes[12+i];
    }
    ByteArray k1 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        k1.bytes[i] = K.bytes[8+i];
    }
    ByteArray k2 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        k2.bytes[i] = K.bytes[4+i];
    }
    ByteArray k3 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        k3.bytes[i] = K.bytes[0+i];
    }
    ByteArray IV0 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        IV0.bytes[i] = IV.bytes[12+i];
    }
    ByteArray IV1 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        IV1.bytes[i] = IV.bytes[8+i];
    }
    ByteArray IV2 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        IV2.bytes[i] = IV.bytes[4+i];
    }
    ByteArray IV3 = ByteArray__from_int(0x0, 4);
    for (int i = 0; i < 4; i++) {
        IV3.bytes[i] = IV.bytes[0+i];
    }

    LFSR[15] = ByteArray__OR(k3, IV0);
    LFSR[14] = k2;
    LFSR[13] = k1;
    LFSR[12] = ByteArray__OR(k0, IV1);
    LFSR[11] = ByteArray__OR(k3, const_all_one);
    LFSR[10] = ByteArray__OR(ByteArray__OR(k2, const_all_one), IV2);
    LFSR[9] = ByteArray__OR(ByteArray__OR(k1, const_all_one), IV3);
    LFSR[8] = ByteArray__OR(k0, const_all_one);
    LFSR[7] = k3;
    LFSR[6] = k2;
    LFSR[5] = k1;
    LFSR[4] = k0;
    LFSR[3] = ByteArray__OR(k3, const_all_one);
    LFSR[2] = ByteArray__OR(k2, const_all_one);
    LFSR[1] = ByteArray__OR(k1, const_all_one);
    LFSR[0] = ByteArray__OR(k0, const_all_one);
    printf("\n");
    ByteArray__print(LFSR[15]);printf("\n");
    ByteArray__print(LFSR[14]);printf("\n");
    ByteArray__print(LFSR[13]);printf("\n");
    ByteArray__print(LFSR[12]);printf("\n");
    
    ByteArray__print(LFSR[11]);printf("\n");
    ByteArray__print(LFSR[10]);printf("\n");
    ByteArray__print(LFSR[9]);printf("\n");
    ByteArray__print(LFSR[8]);printf("\n");
    
    ByteArray__print(LFSR[7]);printf("\n");
    ByteArray__print(LFSR[6]);printf("\n");
    ByteArray__print(LFSR[5]);printf("\n");
    ByteArray__print(LFSR[4]);printf("\n");
    
    ByteArray__print(LFSR[3]);printf("\n");
    ByteArray__print(LFSR[2]);printf("\n");
    ByteArray__print(LFSR[1]);printf("\n");
    ByteArray__print(LFSR[0]);printf("\n");printf("\n");
    
}


// F: 32 bits
void LFSR__initialize_mode(ByteArray F) {
    ByteArray r1 = ByteArray__from_int(0x0, 4);
    r1.bytes[1] = LFSR[0].bytes[0];
    r1.bytes[2] = LFSR[0].bytes[1];
    r1.bytes[3] = LFSR[0].bytes[2];
    
    printf("\n s00\n:\n");
    ByteArray__print(r1);printf("\n");printf("\n");
    
    printf("\n stage11\n:\n");
    ByteArray__print(LFSR[11]);printf("\n");printf("\n");
    
    ByteArray r2 = ByteArray__from_int(0x0, 4);
    r2.bytes[0] = LFSR[11].bytes[1];
    r2.bytes[1] = LFSR[11].bytes[2];
    r2.bytes[2] = LFSR[11].bytes[3];
    
    printf("\n s11 \n:\n");
    ByteArray__print(r2);printf("\n");printf("\n");
    
    ByteArray v = ByteArray__OR(r1, MULa(ByteArray__from_int(LFSR[0].bytes[3], 1)));
    v = ByteArray__OR(v, LFSR[2]);
    v = ByteArray__OR(v, r2);
    v = ByteArray__OR(v, DIVa(ByteArray__from_int(LFSR[11].bytes[0], 1)));
    v = ByteArray__OR(v, F);

    for (int i = 0; i < 15; i++) {
        LFSR[i] = LFSR[i+1];
    }
    LFSR[15] = v;
    printf("\n res \n:\n");
    ByteArray__print(v);printf("\n");printf("\n");
} 


void LFSR__keystream_mode() {
    ByteArray r1 = ByteArray__from_int(0x0, 4);
    r1.bytes[1] = LFSR[0].bytes[0];
    r1.bytes[2] = LFSR[0].bytes[1];
    r1.bytes[3] = LFSR[0].bytes[2];
    
    ByteArray r2 = ByteArray__from_int(0x0, 4);
    r2.bytes[0] = LFSR[11].bytes[1];
    r2.bytes[1] = LFSR[11].bytes[2];
    r2.bytes[2] = LFSR[11].bytes[3];

    ByteArray v = ByteArray__OR(r1, MULa(ByteArray__from_int(LFSR[0].bytes[3], 1)));
    v = ByteArray__OR(v, LFSR[2]);
    v = ByteArray__OR(v, r2);
    v = ByteArray__OR(v, DIVa(ByteArray__from_int(LFSR[11].bytes[0], 1)));

    for (int i = 0; i < 15; i++) {
        LFSR[i] = LFSR[i+1];
    }
    LFSR[15] = v;

    printf("\n res \n:\n");
    ByteArray__print(LFSR[7]);printf("\n");printf("\n");
}




int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: ./cipher INPUT_FILE_NAME\n");
        return 0;
    }

    ByteArray K = ByteArray__from_int(0x0, 16);
    ByteArray IV = ByteArray__from_int(0x0, 16);
    int n = 0;


    FILE *f = fopen(argv[1], "r");

    uint32_t buf;
    for (int i = 0; i < 4; i++) {
        fscanf(f, "%x", &buf);
        for (int j = 0; j < 4; j++) {
            K.bytes[12 - (4 * i) + j] = (buf >> (8 * j)) & 0xFF;
        }
    }
    for (int i = 0; i < 4; i++) {
        fscanf(f, "%x", &buf);
        for (int j = 0; j < 4; j++) {
            IV.bytes[12 - (4 * i) + j] = (buf >> (8 * j)) & 0xFF;
        }
    }
    fscanf(f, "%d", &n);
    fclose(f);

    LFSR__init(K, IV);
    FSM__init();
    for (int i = 0; i < 32; i++) {
        ByteArray F = FSM__clock();
        
        ByteArray__print(F);printf("\n");
        LFSR__initialize_mode(F);
        
        printf("\n\n cycle %d: \n\n",i);
        ByteArray__print(LFSR[15]);printf("\n");
        ByteArray__print(LFSR[14]);printf("\n");
        ByteArray__print(LFSR[13]);printf("\n");
        ByteArray__print(LFSR[12]);printf("\n");
        
        ByteArray__print(LFSR[11]);printf("\n");
        ByteArray__print(LFSR[10]);printf("\n");
        ByteArray__print(LFSR[9]);printf("\n");
        ByteArray__print(LFSR[8]);printf("\n");
        
        ByteArray__print(LFSR[7]);printf("\n");
        ByteArray__print(LFSR[6]);printf("\n");
        ByteArray__print(LFSR[5]);printf("\n");
        ByteArray__print(LFSR[4]);printf("\n");
        
        ByteArray__print(LFSR[3]);printf("\f");
        ByteArray__print(LFSR[2]);printf("\n");
        ByteArray__print(LFSR[1]);printf("\n");
        ByteArray__print(LFSR[0]);printf("\n");
        
        printf("\n");
        ByteArray__print(FSM[0]);
        printf("\n");
        ByteArray__print(FSM[1]);
        printf("\n");
        ByteArray__print(FSM[2]);
        printf("\n");
        
//        if(i==31){
//            return 0;
//        }
    }
    // generation
    FSM__clock();
    LFSR__keystream_mode();
    for (int i = 0; i < n; i++) {
        ByteArray F = FSM__clock();
        ByteArray zt = ByteArray__OR(F, LFSR[0]);
        printf("n\n The final code is:\n");
        ByteArray__print(zt);
        printf("\n");
        LFSR__keystream_mode();
    }
    
}
