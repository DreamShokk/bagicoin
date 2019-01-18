// Copyright (c) 2007-2010  Projet RNRT SAPHIR
// Copyright (c) 2019 PM-Tech
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CUBEHASH512_H
#define CUBEHASH512_H


#include <stddef.h>
#include <crypto/c11_types.h>

/**
 * This structure is a context for LUFFA512 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a BLAKE computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running LUFFA512
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
    unsigned char buf[32];    /* first field, for alignment */
    size_t ptr;
    sph_u32 state[32];
} cubehash_context;

/** A hasher class for CUBEHASH512. */
class CCUBEHASH512
{
private:
    cubehash_context s;

public:
    static const size_t OUTPUT_SIZE = 64;

    CCUBEHASH512();
    CCUBEHASH512& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CCUBEHASH512& Reset();
};

#endif // CUBEHASH512_H
