// Copyright (c) 2007-2010  Projet RNRT SAPHIR
// Copyright (c) 2019 PM-Tech
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BMW512_H
#define BMW512_H

#include <stdint.h>
#include <stdlib.h>
#include <crypto/c11_types.h>

/**
 * This structure is a context for BMW512 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a BLAKE computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running BMW512
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
    unsigned char buf[128];    /* first field, for alignment */
    size_t ptr;
    sph_u64 H[16];
    sph_u64 bit_count;
} bmw_context;

/** A hasher class for BMW512. */
class CBMW512
{
private:
    bmw_context s;

public:
    static const size_t OUTPUT_SIZE = 64;

    CBMW512();
    CBMW512& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CBMW512& Reset();
};

#endif // BMW512_H
