// Copyright (c) 2007-2010  Projet RNRT SAPHIR
// Copyright (c) 2019 PM-Tech
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/echo512.h>

#include <stddef.h>
#include <string.h>
#include <limits.h>

#define T32   SPH_T32
#define C32   SPH_C32
#define C64   SPH_C64

#define DECL_STATE_BIG   \
        sph_u64 W[16][2];

#define INPUT_BLOCK_BIG(sc)   do { \
                unsigned u; \
                memcpy(W, sc->state, 16 * sizeof(sph_u64)); \
                for (u = 0; u < 8; u ++) { \
                        W[u + 8][0] = sph_dec64le_aligned( \
                                sc->buf + 16 * u); \
                        W[u + 8][1] = sph_dec64le_aligned( \
                                sc->buf + 16 * u + 8); \
                } \
        } while (0)

#define AES_2ROUNDS(X)   do { \
                sph_u32 X0 = (sph_u32)(X[0]); \
                sph_u32 X1 = (sph_u32)(X[0] >> 32); \
                sph_u32 X2 = (sph_u32)(X[1]); \
                sph_u32 X3 = (sph_u32)(X[1] >> 32); \
                sph_u32 Y0, Y1, Y2, Y3; \
                AES_ROUND_LE(X0, X1, X2, X3, K0, K1, K2, K3, Y0, Y1, Y2, Y3); \
                AES_ROUND_NOKEY_LE(Y0, Y1, Y2, Y3, X0, X1, X2, X3); \
                X[0] = (sph_u64)X0 | ((sph_u64)X1 << 32); \
                X[1] = (sph_u64)X2 | ((sph_u64)X3 << 32); \
                if ((K0 = T32(K0 + 1)) == 0) { \
                        if ((K1 = T32(K1 + 1)) == 0) \
                                if ((K2 = T32(K2 + 1)) == 0) \
                                        K3 = T32(K3 + 1); \
                } \
        } while (0)

#define BIG_SUB_WORDS   do { \
                AES_2ROUNDS(W[ 0]); \
                AES_2ROUNDS(W[ 1]); \
                AES_2ROUNDS(W[ 2]); \
                AES_2ROUNDS(W[ 3]); \
                AES_2ROUNDS(W[ 4]); \
                AES_2ROUNDS(W[ 5]); \
                AES_2ROUNDS(W[ 6]); \
                AES_2ROUNDS(W[ 7]); \
                AES_2ROUNDS(W[ 8]); \
                AES_2ROUNDS(W[ 9]); \
                AES_2ROUNDS(W[10]); \
                AES_2ROUNDS(W[11]); \
                AES_2ROUNDS(W[12]); \
                AES_2ROUNDS(W[13]); \
                AES_2ROUNDS(W[14]); \
                AES_2ROUNDS(W[15]); \
        } while (0)

#define SHIFT_ROW1(a, b, c, d)   do { \
                sph_u64 tmp; \
                tmp = W[a][0]; \
                W[a][0] = W[b][0]; \
                W[b][0] = W[c][0]; \
                W[c][0] = W[d][0]; \
                W[d][0] = tmp; \
                tmp = W[a][1]; \
                W[a][1] = W[b][1]; \
                W[b][1] = W[c][1]; \
                W[c][1] = W[d][1]; \
                W[d][1] = tmp; \
        } while (0)

#define SHIFT_ROW2(a, b, c, d)   do { \
                sph_u64 tmp; \
                tmp = W[a][0]; \
                W[a][0] = W[c][0]; \
                W[c][0] = tmp; \
                tmp = W[b][0]; \
                W[b][0] = W[d][0]; \
                W[d][0] = tmp; \
                tmp = W[a][1]; \
                W[a][1] = W[c][1]; \
                W[c][1] = tmp; \
                tmp = W[b][1]; \
                W[b][1] = W[d][1]; \
                W[d][1] = tmp; \
        } while (0)

#define SHIFT_ROW3(a, b, c, d)   SHIFT_ROW1(d, c, b, a)

#define BIG_SHIFT_ROWS   do { \
                SHIFT_ROW1(1, 5, 9, 13); \
                SHIFT_ROW2(2, 6, 10, 14); \
                SHIFT_ROW3(3, 7, 11, 15); \
        } while (0)

#define MIX_COLUMN1(ia, ib, ic, id, n)   do { \
                sph_u64 a = W[ia][n]; \
                sph_u64 b = W[ib][n]; \
                sph_u64 c = W[ic][n]; \
                sph_u64 d = W[id][n]; \
                sph_u64 ab = a ^ b; \
                sph_u64 bc = b ^ c; \
                sph_u64 cd = c ^ d; \
                sph_u64 abx = ((ab & C64(0x8080808080808080)) >> 7) * 27U \
                        ^ ((ab & C64(0x7F7F7F7F7F7F7F7F)) << 1); \
                sph_u64 bcx = ((bc & C64(0x8080808080808080)) >> 7) * 27U \
                        ^ ((bc & C64(0x7F7F7F7F7F7F7F7F)) << 1); \
                sph_u64 cdx = ((cd & C64(0x8080808080808080)) >> 7) * 27U \
                        ^ ((cd & C64(0x7F7F7F7F7F7F7F7F)) << 1); \
                W[ia][n] = abx ^ bc ^ d; \
                W[ib][n] = bcx ^ a ^ cd; \
                W[ic][n] = cdx ^ ab ^ d; \
                W[id][n] = abx ^ bcx ^ cdx ^ ab ^ c; \
        } while (0)

#define MIX_COLUMN(a, b, c, d)   do { \
                MIX_COLUMN1(a, b, c, d, 0); \
                MIX_COLUMN1(a, b, c, d, 1); \
        } while (0)

#define BIG_MIX_COLUMNS   do { \
                MIX_COLUMN(0, 1, 2, 3); \
                MIX_COLUMN(4, 5, 6, 7); \
                MIX_COLUMN(8, 9, 10, 11); \
                MIX_COLUMN(12, 13, 14, 15); \
        } while (0)

#define BIG_ROUND   do { \
                BIG_SUB_WORDS; \
                BIG_SHIFT_ROWS; \
                BIG_MIX_COLUMNS; \
        } while (0)

#define FINAL_BIG   do { \
                unsigned u; \
                sph_u64 *VV = &sc->state[0][0]; \
                sph_u64 *WW = &W[0][0]; \
                for (u = 0; u < 16; u ++) { \
                        VV[u] ^= sph_dec64le_aligned(sc->buf + (u * 8)) \
                                ^ WW[u] ^ WW[u + 16]; \
                } \
        } while (0)

#define COMPRESS_BIG(sc)   do { \
                sph_u32 K0 = sc->C0; \
                sph_u32 K1 = sc->C1; \
                sph_u32 K2 = sc->C2; \
                sph_u32 K3 = sc->C3; \
                unsigned u; \
                INPUT_BLOCK_BIG(sc); \
                for (u = 0; u < 10; u ++) { \
                        BIG_ROUND; \
                } \
                FINAL_BIG; \
        } while (0)

#define INCR_COUNTER(sc, val)   do { \
        s.C0 = T32(s.C0 + (sph_u32)(val)); \
        if (s.C0 < (sph_u32)(val)) { \
            if ((s.C1 = T32(s.C1 + 1)) == 0) \
                if ((s.C2 = T32(s.C2 + 1)) == 0) \
                    s.C3 = T32(s.C3 + 1); \
        } \
    } while (0)

////// ECHO512

// Internal implementation code.
namespace
{
/// Internal ECHO512 implementation.
namespace echo512
{

void inline Initialize(echo_context *sc)
{
    sph_u64 k = 512;
    for (int i = 0; i < 8; i++) {
        sc->state[i][0] = k;
        sc->state[i][1] = 0;
    }
    sc->ptr = 0;
    sc->C0 = sc->C1 = sc->C2 = sc->C3 = 0;
}

void inline echo_compress(echo_context *sc)
{
        DECL_STATE_BIG

        COMPRESS_BIG(sc);
}

} // namespace echo512

} // namespace


CECHO512::CECHO512()
{
    echo512::Initialize(&s);
}


CECHO512& CECHO512::Write(const unsigned char* data, size_t len)
{
        unsigned char *buf;
        size_t ptr;

        buf = s.buf;
        ptr = s.ptr;
        if (len < (sizeof s.buf) - ptr) {
                memcpy(buf + ptr, data, len);
                ptr += len;
                s.ptr = ptr;
                return *this;
        }

        while (len > 0) {
                size_t clen;

                clen = (sizeof s.buf) - ptr;
                if (clen > len)
                        clen = len;
                memcpy(buf + ptr, data, clen);
                ptr += clen;
                data += clen;
                len -= clen;
                if (ptr == sizeof s.buf) {
                        INCR_COUNTER(&s, 1024);
                        echo512::echo_compress(&s);
                        ptr = 0;
                }
        }
        s.ptr = ptr;
        return *this;
}

void CECHO512::Finalize(unsigned char hash[OUTPUT_SIZE])
{
        unsigned char *buf;
        size_t ptr;
        unsigned z;
        unsigned elen;
        union {
                unsigned char tmp[64];
                sph_u32 dummy;
                sph_u64 dummy2;
        } u;
        sph_u64 *VV;
        unsigned k;

        buf = s.buf;
        ptr = s.ptr;
        elen = ((unsigned)ptr << 3);
        INCR_COUNTER(&s, elen);
        sph_enc32le_aligned(u.tmp, s.C0);
        sph_enc32le_aligned(u.tmp + 4, s.C1);
        sph_enc32le_aligned(u.tmp + 8, s.C2);
        sph_enc32le_aligned(u.tmp + 12, s.C3);
        /*
         * If elen is zero, then this block actually contains no message
         * bit, only the first padding bit.
         */
        if (elen == 0) {
                s.C0 = s.C1 = s.C2 = s.C3 = 0;
        }
        z = 0x80 >> 0;
        buf[ptr ++] = ((0 & -z) | z) & 0xFF;
        memset(buf + ptr, 0, (sizeof s.buf) - ptr);
        if (ptr > ((sizeof s.buf) - 18)) {
            echo512::echo_compress(&s);
            s.C0 = s.C1 = s.C2 = s.C3 = 0;
            memset(buf, 0, sizeof s.buf);
        }
        sph_enc16le(buf + (sizeof s.buf) - 18, 16 << 5);
        memcpy(buf + (sizeof s.buf) - 16, u.tmp, 16);
        echo512::echo_compress(&s);
        for (VV = &s.state[0][0], k = 0; k < ((16 + 1) >> 1); k ++)
            sph_enc64le_aligned(u.tmp + (k << 3), VV[k]);
        memcpy(hash, u.tmp, 16 << 2);
        Reset();
}

CECHO512& CECHO512::Reset()
{
    echo512::Initialize(&s);
    return *this;
}
