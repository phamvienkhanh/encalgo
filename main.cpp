#include <iostream>
#include <cstdlib>

#include <openssl/evp.h>
#include <string.h>

void chacha20() {
    // 256-bit key
    unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    // IETF nonce = 96-bit
    unsigned char nonce[12] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };

    unsigned char plaintext[] =
        "hello chacha20 poly1305";

    unsigned char ciphertext[128];
    unsigned char tag[16];

    int len;
    int ciphertext_len;

    EVP_CIPHER_CTX *ctx;

    // =========================
    // ENCRYPT
    // =========================

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(
        ctx,
        EVP_chacha20_poly1305(),
        NULL,
        NULL,
        NULL
    );

    // set nonce length
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_AEAD_SET_IVLEN,
        sizeof(nonce),
        NULL
    );

    EVP_EncryptInit_ex(
        ctx,
        NULL,
        NULL,
        key,
        nonce
    );

    EVP_EncryptUpdate(
        ctx,
        ciphertext,
        &len,
        plaintext,
        strlen((char*)plaintext)
    );

    ciphertext_len = len;

    EVP_EncryptFinal_ex(
        ctx,
        ciphertext + len,
        &len
    );

    ciphertext_len += len;

    // get auth tag
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_AEAD_GET_TAG,
        16,
        tag
    );

    EVP_CIPHER_CTX_free(ctx);
}

void aesgcm(EVP_CIPHER_CTX *ctx) {
    // 256-bit key
    unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    // 96-bit nonce (recommended for GCM)
    unsigned char nonce[12] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };

    unsigned char plaintext[] =
        "hello aes256 gcm";

    unsigned char ciphertext[128];
    unsigned char tag[16];

    int len;
    int ciphertext_len;

    // =========================
    // ENCRYPT
    // =========================


    EVP_EncryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        NULL,
        NULL,
        NULL
    );

    // set IV length
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        sizeof(nonce),
        NULL
    );

    EVP_EncryptInit_ex(
        ctx,
        NULL,
        NULL,
        key,
        nonce
    );

    EVP_EncryptUpdate(
        ctx,
        ciphertext,
        &len,
        plaintext,
        strlen((char*)plaintext)
    );

    ciphertext_len = len;

    EVP_EncryptFinal_ex(
        ctx,
        ciphertext + len,
        &len
    );

    ciphertext_len += len;

    // get auth tag
    EVP_CIPHER_CTX_ctrl(
        ctx,
        EVP_CTRL_GCM_GET_TAG,
        16,
        tag
    );
}




static double now_sec()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec + ts.tv_nsec / 1e9;
}


typedef unsigned int word32;

#define STATE_SIZE 24
#define STATE_COL 6
#define STATE_ROW 4
#define KEY_SIZE 8
#define NONCE_SIZE 4
#define NUM_ROUND 10*10

#define ROTL32(w, r) ((w << r) | (w >> (32u - r)))

static const word32 RC[8] = {
    0x1FFFFFFF, 0x2FFFFFFF, 0x3FFFFFFF, 0x4FFFFFFF,
    0x5FFFFFFF, 0x6FFFFFFF, 0x7FFFFFFF, 0x8FFFFFFF
};

void print_state(word32 state[STATE_SIZE]) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 6; j++) {
            printf("%.8x ", *(state + i*6 + j));
        }
        printf("\n");
    }
}

/*
w0   w1   w2   w3  w4  w5
w6   w7   w8   w9  w10 w11
w12  w13  w14  w15 w16 w17
w18  w19  w20  w21 w22 w23
*/
/*
0 0 c c c c
n n n n 0 0
0 0 0 0 k k
k k k k k k 
*/
void InitState(word32 state[STATE_SIZE], const word32 key[KEY_SIZE], const word32 nonce[NONCE_SIZE]) {
    state[0] = 0x00;
    state[1] = 0x00;
    state[2] = 0x01;
    state[3] = 0x02;
    state[4] = 0x03;
    state[5] = 0x04;
    state[6] = nonce[0];
    state[7] = nonce[1];
    state[8] = nonce[2];
    state[9] = nonce[3];
    state[10] = 0x00;
    state[11] = 0x00;
    state[12] = 0x00;
    state[13] = 0x00;
    state[14] = 0x00;
    state[15] = 0x00;
    state[16] = key[0];
    state[17] = key[1];
    state[18] = key[2];
    state[19] = key[3];
    state[20] = key[4];
    state[21] = key[5];
    state[22] = key[6];
    state[23] = key[7];
}

void WDL(word32 state[STATE_SIZE]) {
    state[0] = state[0] + ROTL32(state[STATE_SIZE-1], 11);
    for(int i = 1; i < STATE_SIZE; i++) {
        state[i] += ROTL32(state[i-1], 11);
    }

    state[STATE_SIZE-1] = state[STATE_SIZE-1] + ROTL32(state[0], 19);
    for(int i = STATE_SIZE - 2; i >= 0; i--) {
        state[i] += ROTL32(state[i+1], 19);
    }
}

void GSL(word32 state[STATE_SIZE]) {
    word32 t1, t2, t3;

    // ROT ROWS
    t1 = state[6];
    state[6] = state[7];
    state[7] = state[8];
    state[8] = state[9];
    state[9] = state[10];
    state[10] = state[11];
    state[11] = t1;
    
    t1 = state[12];
    t2 = state[13];
    state[12] = state[14];
    state[13] = state[15];
    state[14] = state[16];
    state[15] = state[17];
    state[16] = t1;
    state[17] = t2;

    t1 = state[18];
    t2 = state[19];
    t3 = state[20];
    state[18] = state[21];
    state[19] = state[22];
    state[20] = state[23];
    state[21] = t1;
    state[22] = t2;
    state[23] = t3;

    // ROT COL
    t1 = state[1];
    state[1] = state[7];
    state[7] = state[13];
    state[13] = state[19];
    state[19] = t1;

    t1 = state[2];
    t2 = state[8];
    state[2] = state[14];
    state[8] = state[20];
    state[14] = t1;
    state[19] = t2;

    t1 = state[3];
    t2 = state[9];
    t3 = state[15];
    state[3] = state[21];
    state[9] = t1;
    state[15] = t2;
    state[21] = t3;

    t1 = state[5];
    state[5] = state[11];
    state[11] = state[17];
    state[17] = state[23];
    state[23] = t1;
}

#define CCL_ROW(w0, w1, w2, w3, w4, w5) \
    t0 = w0;                            \
    t1 = w1;                            \
    w0 ^= (~w1) & w2;                   \
    w1 ^= (~w2) & w3;                   \
    w2 ^= (~w3) & w4;                   \
    w3 ^= (~w4) & t0;                   \
    w4 ^= (~t0) & t1;

void CCL(word32 state[STATE_SIZE]) {
    word32 t0, t1;
    CCL_ROW(state[0],  state[1],  state[2],  state[3],  state[4],  state[5]);
    CCL_ROW(state[6],  state[7],  state[8],  state[9],  state[10], state[11]);
    CCL_ROW(state[12], state[13], state[14], state[15], state[16], state[17]);
    CCL_ROW(state[18], state[19], state[20], state[21], state[22], state[23]);
}

void RIL(word32 state[STATE_SIZE], word32 r) {
    state[0] ^= RC[0];
}

void Permultion(word32 state[STATE_SIZE])
{
    for (int i = 0; i < NUM_ROUND; i++)
    {
        RIL(state, i);
        GSL(state);
        CCL(state);
        WDL(state);
    }
}

int main(int, char**){
    word32 key[KEY_SIZE]{0};
    key[0] = 4;
    key[7] = 3;
    word32 nonce[NONCE_SIZE]{0};
    nonce[0] = 1;
    nonce[3] = 2;
    word32 state[STATE_SIZE];

    InitState(state, key, nonce);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    double t1, t2, elapsed;
    t1 = now_sec();
    // chacha20();
    aesgcm(ctx);
    t2 = now_sec();
    elapsed = t2 - t1;
    printf("Time: %.40f sec\n", elapsed);

    t1 = now_sec();
    Permultion(state);
    t2 = now_sec();
    elapsed = t2 - t1;
    printf("Time: %.40f sec\n", elapsed);


    print_state(state);

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
