// Copyright (c) 2007-2010  Projet RNRT SAPHIR
// Copyright (c) 2019 PM-Tech
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KECCAK512_H
#define KECCAK512_H

#include <stddef.h>
#include <crypto/c11_types.h>

/**
 * This structure is a context for KECCAK512 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a BLAKE computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running KECCAK512
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
    unsigned char buf[144];    /* first field, for alignment */
    size_t ptr, lim;
    sph_u64 state[25];
} keccak_context;

/** A hasher class for KECCAK512. */
class CKECCAK512
{
private:
    keccak_context s;

public:
    static const size_t OUTPUT_SIZE = 64;

    CKECCAK512();
    CKECCAK512& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CKECCAK512& Reset();
};

#endif // KECCAK512_H
