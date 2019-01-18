/* $Id: sph_types.h 260 2011-07-21 01:02:38Z tp $ */
/**
 * Basic type definitions.
 *
 * This header file defines the generic integer types that will be used
 * for the implementation of hash functions; it also contains helper
 * functions which encode and decode multi-byte integer values, using
 * either little-endian or big-endian conventions.
 *
 * This file contains a compile-time test on the size of a byte
 * (the <code>unsigned char</code> C type). If bytes are not octets,
 * i.e. if they do not have a size of exactly 8 bits, then compilation
 * is aborted. Architectures where bytes are not octets are relatively
 * rare, even in the embedded devices market. We forbid non-octet bytes
 * because there is no clear convention on how octet streams are encoded
 * on such systems.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_types.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_TYPES_H__
#define SPH_TYPES_H__

#include <limits.h>

/*
 * All our I/O functions are defined over octet streams. We do not know
 * how to handle input data if bytes are not octets.
 */
#if CHAR_BIT != 8
#error This code requires 8-bit bytes
#endif

/* ============= BEGIN documentation block for Doxygen ============ */

#ifdef DOXYGEN_IGNORE

/** @mainpage sphlib C code documentation
 *
 * @section overview Overview
 *
 * <code>sphlib</code> is a library which contains implementations of
 * various cryptographic hash functions. These pages have been generated
 * with <a href="http://www.doxygen.org/index.html">doxygen</a> and
 * document the API for the C implementations.
 *
 * The API is described in appropriate header files, which are available
 * in the "Files" section. Each hash function family has its own header,
 * whose name begins with <code>"sph_"</code> and contains the family
 * name. For instance, the API for the RIPEMD hash functions is available
 * in the header file <code>sph_ripemd.h</code>.
 *
 * @section principles API structure and conventions
 *
 * @subsection io Input/output conventions
 *
 * In all generality, hash functions operate over strings of bits.
 * Individual bits are rarely encountered in C programming or actual
 * communication protocols; most protocols converge on the ubiquitous
 * "octet" which is a group of eight bits. Data is thus expressed as a
 * stream of octets. The C programming language contains the notion of a
 * "byte", which is a data unit managed under the type <code>"unsigned
 * char"</code>. The C standard prescribes that a byte should hold at
 * least eight bits, but possibly more. Most modern architectures, even
 * in the embedded world, feature eight-bit bytes, i.e. map bytes to
 * octets.
 *
 * Nevertheless, for some of the implemented hash functions, an extra
 * API has been added, which allows the input of arbitrary sequences of
 * bits: when the computation is about to be closed, 1 to 7 extra bits
 * can be added. The functions for which this API is implemented include
 * the SHA-2 functions and all SHA-3 candidates.
 *
 * <code>sphlib</code> defines hash function which may hash octet streams,
 * i.e. streams of bits where the number of bits is a multiple of eight.
 * The data input functions in the <code>sphlib</code> API expect data
 * as anonymous pointers (<code>"const void *"</code>) with a length
 * (of type <code>"size_t"</code>) which gives the input data chunk length
 * in bytes. A byte is assumed to be an octet; the <code>sph_types.h</code>
 * header contains a compile-time test which prevents compilation on
 * architectures where this property is not met.
 *
 * The hash function output is also converted into bytes. All currently
 * implemented hash functions have an output width which is a multiple of
 * eight, and this is likely to remain true for new designs.
 *
 * Most hash functions internally convert input data into 32-bit of 64-bit
 * words, using either little-endian or big-endian conversion. The hash
 * output also often consists of such words, which are encoded into output
 * bytes with a similar endianness convention. Some hash functions have
 * been only loosely specified on that subject; when necessary,
 * <code>sphlib</code> has been tested against published "reference"
 * implementations in order to use the same conventions.
 *
 * @subsection shortname Function short name
 *
 * Each implemented hash function has a "short name" which is used
 * internally to derive the identifiers for the functions and context
 * structures which the function uses. For instance, MD5 has the short
 * name <code>"md5"</code>. Short names are listed in the next section,
 * for the implemented hash functions. In subsequent sections, the
 * short name will be assumed to be <code>"XXX"</code>: replace with the
 * actual hash function name to get the C identifier.
 *
 * Note: some functions within the same family share the same core
 * elements, such as update function or context structure. Correspondingly,
 * some of the defined types or functions may actually be macros which
 * transparently evaluate to another type or function name.
 *
 * @subsection context Context structure
 *
 * Each implemented hash fonction has its own context structure, available
 * under the type name <code>"sph_XXX_context"</code> for the hash function
 * with short name <code>"XXX"</code>. This structure holds all needed
 * state for a running hash computation.
 *
 * The contents of these structures are meant to be opaque, and private
 * to the implementation. However, these contents are specified in the
 * header files so that application code which uses <code>sphlib</code>
 * may access the size of those structures.
 *
 * The caller is responsible for allocating the context structure,
 * whether by dynamic allocation (<code>malloc()</code> or equivalent),
 * static allocation (a global permanent variable), as an automatic
 * variable ("on the stack"), or by any other mean which ensures proper
 * structure alignment. <code>sphlib</code> code performs no dynamic
 * allocation by itself.
 *
 * The context must be initialized before use, using the
 * <code>sph_XXX_init()</code> function. This function sets the context
 * state to proper initial values for hashing.
 *
 * Since all state data is contained within the context structure,
 * <code>sphlib</code> is thread-safe and reentrant: several hash
 * computations may be performed in parallel, provided that they do not
 * operate on the same context. Moreover, a running computation can be
 * cloned by copying the context (with a simple <code>memcpy()</code>):
 * the context and its clone are then independant and may be updated
 * with new data and/or closed without interfering with each other.
 * Similarly, a context structure can be moved in memory at will:
 * context structures contain no pointer, in particular no pointer to
 * themselves.
 *
 * @subsection dataio Data input
 *
 * Hashed data is input with the <code>sph_XXX()</code> fonction, which
 * takes as parameters a pointer to the context, a pointer to the data
 * to hash, and the number of data bytes to hash. The context is updated
 * with the new data.
 *
 * Data can be input in one or several calls, with arbitrary input lengths.
 * However, it is best, performance wise, to input data by relatively big
 * chunks (say a few kilobytes), because this allows <code>sphlib</code> to
 * optimize things and avoid internal copying.
 *
 * When all data has been input, the context can be closed with
 * <code>sph_XXX_close()</code>. The hash output is computed and written
 * into the provided buffer. The caller must take care to provide a
 * buffer of appropriate length; e.g., when using SHA-1, the output is
 * a 20-byte word, therefore the output buffer must be at least 20-byte
 * long.
 *
 * For some hash functions, the <code>sph_XXX_addbits_and_close()</code>
 * function can be used instead of <code>sph_XXX_close()</code>. This
 * function can take a few extra <strong>bits</strong> to be added at
 * the end of the input message. This allows hashing messages with a
 * bit length which is not a multiple of 8. The extra bits are provided
 * as an unsigned integer value, and a bit count. The bit count must be
 * between 0 and 7, inclusive. The extra bits are provided as bits 7 to
 * 0 (bits of numerical value 128, 64, 32... downto 0), in that order.
 * For instance, to add three bits of value 1, 1 and 0, the unsigned
 * integer will have value 192 (1*128 + 1*64 + 0*32) and the bit count
 * will be 3.
 *
 * The <code>SPH_SIZE_XXX</code> macro is defined for each hash function;
 * it evaluates to the function output size, expressed in bits. For instance,
 * <code>SPH_SIZE_sha1</code> evaluates to <code>160</code>.
 *
 * When closed, the context is automatically reinitialized and can be
 * immediately used for another computation. It is not necessary to call
 * <code>sph_XXX_init()</code> after a close. Note that
 * <code>sph_XXX_init()</code> can still be called to "reset" a context,
 * i.e. forget previously input data, and get back to the initial state.
 *
 * @subsection alignment Data alignment
 *
 * "Alignment" is a property of data, which is said to be "properly
 * aligned" when its emplacement in memory is such that the data can
 * be optimally read by full words. This depends on the type of access;
 * basically, some hash functions will read data by 32-bit or 64-bit
 * words. <code>sphlib</code> does not mandate such alignment for input
 * data, but using aligned data can substantially improve performance.
 *
 * As a rule, it is best to input data by chunks whose length (in bytes)
 * is a multiple of eight, and which begins at "generally aligned"
 * addresses, such as the base address returned by a call to
 * <code>malloc()</code>.
 *
 * @section functions Implemented functions
 *
 * We give here the list of implemented functions. They are grouped by
 * family; to each family corresponds a specific header file. Each
 * individual function has its associated "short name". Please refer to
 * the documentation for that header file to get details on the hash
 * function denomination and provenance.
 *
 * Note: the functions marked with a '(64)' in the list below are
 * available only if the C compiler provides an integer type of length
 * 64 bits or more. Such a type is mandatory in the latest C standard
 * (ISO 9899:1999, aka "C99") and is present in several older compilers
 * as well, so chances are that such a type is available.
 *
 * - HAVAL family: file <code>sph_haval.h</code>
 *   - HAVAL-128/3 (128-bit, 3 passes): short name: <code>haval128_3</code>
 *   - HAVAL-128/4 (128-bit, 4 passes): short name: <code>haval128_4</code>
 *   - HAVAL-128/5 (128-bit, 5 passes): short name: <code>haval128_5</code>
 *   - HAVAL-160/3 (160-bit, 3 passes): short name: <code>haval160_3</code>
 *   - HAVAL-160/4 (160-bit, 4 passes): short name: <code>haval160_4</code>
 *   - HAVAL-160/5 (160-bit, 5 passes): short name: <code>haval160_5</code>
 *   - HAVAL-192/3 (192-bit, 3 passes): short name: <code>haval192_3</code>
 *   - HAVAL-192/4 (192-bit, 4 passes): short name: <code>haval192_4</code>
 *   - HAVAL-192/5 (192-bit, 5 passes): short name: <code>haval192_5</code>
 *   - HAVAL-224/3 (224-bit, 3 passes): short name: <code>haval224_3</code>
 *   - HAVAL-224/4 (224-bit, 4 passes): short name: <code>haval224_4</code>
 *   - HAVAL-224/5 (224-bit, 5 passes): short name: <code>haval224_5</code>
 *   - HAVAL-256/3 (256-bit, 3 passes): short name: <code>haval256_3</code>
 *   - HAVAL-256/4 (256-bit, 4 passes): short name: <code>haval256_4</code>
 *   - HAVAL-256/5 (256-bit, 5 passes): short name: <code>haval256_5</code>
 * - MD2: file <code>sph_md2.h</code>, short name: <code>md2</code>
 * - MD4: file <code>sph_md4.h</code>, short name: <code>md4</code>
 * - MD5: file <code>sph_md5.h</code>, short name: <code>md5</code>
 * - PANAMA: file <code>sph_panama.h</code>, short name: <code>panama</code>
 * - RadioGatun family: file <code>sph_radiogatun.h</code>
 *   - RadioGatun[32]: short name: <code>radiogatun32</code>
 *   - RadioGatun[64]: short name: <code>radiogatun64</code> (64)
 * - RIPEMD family: file <code>sph_ripemd.h</code>
 *   - RIPEMD: short name: <code>ripemd</code>
 *   - RIPEMD-128: short name: <code>ripemd128</code>
 *   - RIPEMD-160: short name: <code>ripemd160</code>
 * - SHA-0: file <code>sph_sha0.h</code>, short name: <code>sha0</code>
 * - SHA-1: file <code>sph_sha1.h</code>, short name: <code>sha1</code>
 * - SHA-2 family, 32-bit hashes: file <code>sph_sha2.h</code>
 *   - SHA-224: short name: <code>sha224</code>
 *   - SHA-256: short name: <code>sha256</code>
 *   - SHA-384: short name: <code>sha384</code> (64)
 *   - SHA-512: short name: <code>sha512</code> (64)
 * - Tiger family: file <code>sph_tiger.h</code>
 *   - Tiger: short name: <code>tiger</code> (64)
 *   - Tiger2: short name: <code>tiger2</code> (64)
 * - WHIRLPOOL family: file <code>sph_whirlpool.h</code>
 *   - WHIRLPOOL-0: short name: <code>whirlpool0</code> (64)
 *   - WHIRLPOOL-1: short name: <code>whirlpool1</code> (64)
 *   - WHIRLPOOL: short name: <code>whirlpool</code> (64)
 *
 * The fourteen second-round SHA-3 candidates are also implemented;
 * when applicable, the implementations follow the "final" specifications
 * as published for the third round of the SHA-3 competition (BLAKE,
 * Groestl, JH, Keccak and Skein have been tweaked for third round).
 *
 * - BLAKE family: file <code>sph_blake.h</code>
 *   - BLAKE-224: short name: <code>blake224</code>
 *   - BLAKE-256: short name: <code>blake256</code>
 *   - BLAKE-384: short name: <code>blake384</code>
 *   - BLAKE-512: short name: <code>blake512</code>
 * - BMW (Blue Midnight Wish) family: file <code>sph_bmw.h</code>
 *   - BMW-224: short name: <code>bmw224</code>
 *   - BMW-256: short name: <code>bmw256</code>
 *   - BMW-384: short name: <code>bmw384</code> (64)
 *   - BMW-512: short name: <code>bmw512</code> (64)
 * - CubeHash family: file <code>sph_cubehash.h</code> (specified as
 *   CubeHash16/32 in the CubeHash specification)
 *   - CubeHash-224: short name: <code>cubehash224</code>
 *   - CubeHash-256: short name: <code>cubehash256</code>
 *   - CubeHash-384: short name: <code>cubehash384</code>
 *   - CubeHash-512: short name: <code>cubehash512</code>
 * - ECHO family: file <code>sph_echo.h</code>
 *   - ECHO-224: short name: <code>echo224</code>
 *   - ECHO-256: short name: <code>echo256</code>
 *   - ECHO-384: short name: <code>echo384</code>
 *   - ECHO-512: short name: <code>echo512</code>
 * - Fugue family: file <code>sph_fugue.h</code>
 *   - Fugue-224: short name: <code>fugue224</code>
 *   - Fugue-256: short name: <code>fugue256</code>
 *   - Fugue-384: short name: <code>fugue384</code>
 *   - Fugue-512: short name: <code>fugue512</code>
 * - Groestl family: file <code>sph_groestl.h</code>
 *   - Groestl-224: short name: <code>groestl224</code>
 *   - Groestl-256: short name: <code>groestl256</code>
 *   - Groestl-384: short name: <code>groestl384</code>
 *   - Groestl-512: short name: <code>groestl512</code>
 * - Hamsi family: file <code>sph_hamsi.h</code>
 *   - Hamsi-224: short name: <code>hamsi224</code>
 *   - Hamsi-256: short name: <code>hamsi256</code>
 *   - Hamsi-384: short name: <code>hamsi384</code>
 *   - Hamsi-512: short name: <code>hamsi512</code>
 * - JH family: file <code>sph_jh.h</code>
 *   - JH-224: short name: <code>jh224</code>
 *   - JH-256: short name: <code>jh256</code>
 *   - JH-384: short name: <code>jh384</code>
 *   - JH-512: short name: <code>jh512</code>
 * - Keccak family: file <code>sph_keccak.h</code>
 *   - Keccak-224: short name: <code>keccak224</code>
 *   - Keccak-256: short name: <code>keccak256</code>
 *   - Keccak-384: short name: <code>keccak384</code>
 *   - Keccak-512: short name: <code>keccak512</code>
 * - Luffa family: file <code>sph_luffa.h</code>
 *   - Luffa-224: short name: <code>luffa224</code>
 *   - Luffa-256: short name: <code>luffa256</code>
 *   - Luffa-384: short name: <code>luffa384</code>
 *   - Luffa-512: short name: <code>luffa512</code>
 * - Shabal family: file <code>sph_shabal.h</code>
 *   - Shabal-192: short name: <code>shabal192</code>
 *   - Shabal-224: short name: <code>shabal224</code>
 *   - Shabal-256: short name: <code>shabal256</code>
 *   - Shabal-384: short name: <code>shabal384</code>
 *   - Shabal-512: short name: <code>shabal512</code>
 * - SHAvite-3 family: file <code>sph_shavite.h</code>
 *   - SHAvite-224 (nominally "SHAvite-3 with 224-bit output"):
 *     short name: <code>shabal224</code>
 *   - SHAvite-256 (nominally "SHAvite-3 with 256-bit output"):
 *     short name: <code>shabal256</code>
 *   - SHAvite-384 (nominally "SHAvite-3 with 384-bit output"):
 *     short name: <code>shabal384</code>
 *   - SHAvite-512 (nominally "SHAvite-3 with 512-bit output"):
 *     short name: <code>shabal512</code>
 * - SIMD family: file <code>sph_simd.h</code>
 *   - SIMD-224: short name: <code>simd224</code>
 *   - SIMD-256: short name: <code>simd256</code>
 *   - SIMD-384: short name: <code>simd384</code>
 *   - SIMD-512: short name: <code>simd512</code>
 * - Skein family: file <code>sph_skein.h</code>
 *   - Skein-224 (nominally specified as Skein-512-224): short name:
 *     <code>skein224</code> (64)
 *   - Skein-256 (nominally specified as Skein-512-256): short name:
 *     <code>skein256</code> (64)
 *   - Skein-384 (nominally specified as Skein-512-384): short name:
 *     <code>skein384</code> (64)
 *   - Skein-512 (nominally specified as Skein-512-512): short name:
 *     <code>skein512</code> (64)
 *
 * For the second-round SHA-3 candidates, the functions are as specified
 * for round 2, i.e. with the "tweaks" that some candidates added
 * between round 1 and round 2. Also, some of the submitted packages for
 * round 2 contained errors, in the specification, reference code, or
 * both. <code>sphlib</code> implements the corrected versions.
 */

/** @hideinitializer
 * Unsigned integer type whose length is at least 32 bits; on most
 * architectures, it will have a width of exactly 32 bits. Unsigned C
 * types implement arithmetics modulo a power of 2; use the
 * <code>SPH_T32()</code> macro to ensure that the value is truncated
 * to exactly 32 bits. Unless otherwise specified, all macros and
 * functions which accept <code>sph_u32</code> values assume that these
 * values fit on 32 bits, i.e. do not exceed 2^32-1, even on architectures
 * where <code>sph_u32</code> is larger than that.
 */
typedef __arch_dependant__ sph_u32;

/** @hideinitializer
 * Signed integer type corresponding to <code>sph_u32</code>; it has
 * width 32 bits or more.
 */
typedef __arch_dependant__ sph_s32;

/** @hideinitializer
 * Unsigned integer type whose length is at least 64 bits; on most
 * architectures which feature such a type, it will have a width of
 * exactly 64 bits. C99-compliant platform will have this type; it
 * is also defined when the GNU compiler (gcc) is used, and on
 * platforms where <code>unsigned long</code> is large enough. If this
 * type is not available, then some hash functions which depends on
 * a 64-bit type will not be available (most notably SHA-384, SHA-512,
 * Tiger and WHIRLPOOL).
 */
typedef __arch_dependant__ sph_u64;

/** @hideinitializer
 * Signed integer type corresponding to <code>sph_u64</code>; it has
 * width 64 bits or more.
 */
typedef __arch_dependant__ sph_s64;

/**
 * This macro expands the token <code>x</code> into a suitable
 * constant expression of type <code>sph_u32</code>. Depending on
 * how this type is defined, a suffix such as <code>UL</code> may
 * be appended to the argument.
 *
 * @param x   the token to expand into a suitable constant expression
 */
#define SPH_C32(x)

/**
 * Truncate a 32-bit value to exactly 32 bits. On most systems, this is
 * a no-op, recognized as such by the compiler.
 *
 * @param x   the value to truncate (of type <code>sph_u32</code>)
 */
#define SPH_T32(x)

/**
 * Rotate a 32-bit value by a number of bits to the left. The rotate
 * count must reside between 1 and 31. This macro assumes that its
 * first argument fits in 32 bits (no extra bit allowed on machines where
 * <code>sph_u32</code> is wider); both arguments may be evaluated
 * several times.
 *
 * @param x   the value to rotate (of type <code>sph_u32</code>)
 * @param n   the rotation count (between 1 and 31, inclusive)
 */
#define SPH_ROTL32(x, n)

/**
 * Rotate a 32-bit value by a number of bits to the left. The rotate
 * count must reside between 1 and 31. This macro assumes that its
 * first argument fits in 32 bits (no extra bit allowed on machines where
 * <code>sph_u32</code> is wider); both arguments may be evaluated
 * several times.
 *
 * @param x   the value to rotate (of type <code>sph_u32</code>)
 * @param n   the rotation count (between 1 and 31, inclusive)
 */
#define SPH_ROTR32(x, n)

/**
 * This macro is defined on systems for which a 64-bit type has been
 * detected, and is used for <code>sph_u64</code>.
 */
#define SPH_64

/**
 * This macro is defined on systems for the "native" integer size is
 * 64 bits (64-bit values fit in one register).
 */
#define SPH_64_TRUE

/**
 * This macro expands the token <code>x</code> into a suitable
 * constant expression of type <code>sph_u64</code>. Depending on
 * how this type is defined, a suffix such as <code>ULL</code> may
 * be appended to the argument. This macro is defined only if a
 * 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param x   the token to expand into a suitable constant expression
 */
#define SPH_C64(x)

/**
 * Truncate a 64-bit value to exactly 64 bits. On most systems, this is
 * a no-op, recognized as such by the compiler. This macro is defined only
 * if a 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param x   the value to truncate (of type <code>sph_u64</code>)
 */
#define SPH_T64(x)

/**
 * Rotate a 64-bit value by a number of bits to the left. The rotate
 * count must reside between 1 and 63. This macro assumes that its
 * first argument fits in 64 bits (no extra bit allowed on machines where
 * <code>sph_u64</code> is wider); both arguments may be evaluated
 * several times. This macro is defined only if a 64-bit type was detected
 * and used for <code>sph_u64</code>.
 *
 * @param x   the value to rotate (of type <code>sph_u64</code>)
 * @param n   the rotation count (between 1 and 63, inclusive)
 */
#define SPH_ROTL64(x, n)

/**
 * Rotate a 64-bit value by a number of bits to the left. The rotate
 * count must reside between 1 and 63. This macro assumes that its
 * first argument fits in 64 bits (no extra bit allowed on machines where
 * <code>sph_u64</code> is wider); both arguments may be evaluated
 * several times. This macro is defined only if a 64-bit type was detected
 * and used for <code>sph_u64</code>.
 *
 * @param x   the value to rotate (of type <code>sph_u64</code>)
 * @param n   the rotation count (between 1 and 63, inclusive)
 */
#define SPH_ROTR64(x, n)

/**
 * This macro evaluates to <code>inline</code> or an equivalent construction,
 * if available on the compilation platform, or to nothing otherwise. This
 * is used to declare inline functions, for which the compiler should
 * endeavour to include the code directly in the caller. Inline functions
 * are typically defined in header files as replacement for macros.
 */
#define SPH_INLINE

/**
 * This macro is defined if the platform has been detected as using
 * little-endian convention. This implies that the <code>sph_u32</code>
 * type (and the <code>sph_u64</code> type also, if it is defined) has
 * an exact width (i.e. exactly 32-bit, respectively 64-bit).
 */
#define SPH_LITTLE_ENDIAN

/**
 * This macro is defined if the platform has been detected as using
 * big-endian convention. This implies that the <code>sph_u32</code>
 * type (and the <code>sph_u64</code> type also, if it is defined) has
 * an exact width (i.e. exactly 32-bit, respectively 64-bit).
 */
#define SPH_BIG_ENDIAN

/**
 * This macro is defined if 32-bit words (and 64-bit words, if defined)
 * can be read from and written to memory efficiently in little-endian
 * convention. This is the case for little-endian platforms, and also
 * for the big-endian platforms which have special little-endian access
 * opcodes (e.g. Ultrasparc).
 */
#define SPH_LITTLE_FAST

/**
 * This macro is defined if 32-bit words (and 64-bit words, if defined)
 * can be read from and written to memory efficiently in big-endian
 * convention. This is the case for little-endian platforms, and also
 * for the little-endian platforms which have special big-endian access
 * opcodes.
 */
#define SPH_BIG_FAST

/**
 * On some platforms, this macro is defined to an unsigned integer type
 * into which pointer values may be cast. The resulting value can then
 * be tested for being a multiple of 2, 4 or 8, indicating an aligned
 * pointer for, respectively, 16-bit, 32-bit or 64-bit memory accesses.
 */
#define SPH_UPTR

/**
 * When defined, this macro indicates that unaligned memory accesses
 * are possible with only a minor penalty, and thus should be prefered
 * over strategies which first copy data to an aligned buffer.
 */
#define SPH_UNALIGNED

/**
 * Byte-swap a 32-bit word (i.e. <code>0x12345678</code> becomes
 * <code>0x78563412</code>). This is an inline function which resorts
 * to inline assembly on some platforms, for better performance.
 *
 * @param x   the 32-bit value to byte-swap
 * @return  the byte-swapped value
 */
static inline sph_u32 sph_bswap32(sph_u32 x);

/**
 * Byte-swap a 64-bit word. This is an inline function which resorts
 * to inline assembly on some platforms, for better performance. This
 * function is defined only if a suitable 64-bit type was found for
 * <code>sph_u64</code>
 *
 * @param x   the 64-bit value to byte-swap
 * @return  the byte-swapped value
 */
static inline sph_u64 sph_bswap64(sph_u64 x);

/**
 * Decode a 16-bit unsigned value from memory, in little-endian convention
 * (least significant byte comes first).
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline unsigned sph_dec16le(const void *src);

/**
 * Encode a 16-bit unsigned value into memory, in little-endian convention
 * (least significant byte comes first).
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc16le(void *dst, unsigned val);

/**
 * Decode a 16-bit unsigned value from memory, in big-endian convention
 * (most significant byte comes first).
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline unsigned sph_dec16be(const void *src);

/**
 * Encode a 16-bit unsigned value into memory, in big-endian convention
 * (most significant byte comes first).
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc16be(void *dst, unsigned val);

/**
 * Decode a 32-bit unsigned value from memory, in little-endian convention
 * (least significant byte comes first).
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u32 sph_dec32le(const void *src);

/**
 * Decode a 32-bit unsigned value from memory, in little-endian convention
 * (least significant byte comes first). This function assumes that the
 * source address is suitably aligned for a direct access, if the platform
 * supports such things; it can thus be marginally faster than the generic
 * <code>sph_dec32le()</code> function.
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u32 sph_dec32le_aligned(const void *src);

/**
 * Encode a 32-bit unsigned value into memory, in little-endian convention
 * (least significant byte comes first).
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc32le(void *dst, sph_u32 val);

/**
 * Encode a 32-bit unsigned value into memory, in little-endian convention
 * (least significant byte comes first). This function assumes that the
 * destination address is suitably aligned for a direct access, if the
 * platform supports such things; it can thus be marginally faster than
 * the generic <code>sph_enc32le()</code> function.
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc32le_aligned(void *dst, sph_u32 val);

/**
 * Decode a 32-bit unsigned value from memory, in big-endian convention
 * (most significant byte comes first).
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u32 sph_dec32be(const void *src);

/**
 * Decode a 32-bit unsigned value from memory, in big-endian convention
 * (most significant byte comes first). This function assumes that the
 * source address is suitably aligned for a direct access, if the platform
 * supports such things; it can thus be marginally faster than the generic
 * <code>sph_dec32be()</code> function.
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u32 sph_dec32be_aligned(const void *src);

/**
 * Encode a 32-bit unsigned value into memory, in big-endian convention
 * (most significant byte comes first).
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc32be(void *dst, sph_u32 val);

/**
 * Encode a 32-bit unsigned value into memory, in big-endian convention
 * (most significant byte comes first). This function assumes that the
 * destination address is suitably aligned for a direct access, if the
 * platform supports such things; it can thus be marginally faster than
 * the generic <code>sph_enc32be()</code> function.
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc32be_aligned(void *dst, sph_u32 val);

/**
 * Decode a 64-bit unsigned value from memory, in little-endian convention
 * (least significant byte comes first). This function is defined only
 * if a suitable 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u64 sph_dec64le(const void *src);

/**
 * Decode a 64-bit unsigned value from memory, in little-endian convention
 * (least significant byte comes first). This function assumes that the
 * source address is suitably aligned for a direct access, if the platform
 * supports such things; it can thus be marginally faster than the generic
 * <code>sph_dec64le()</code> function. This function is defined only
 * if a suitable 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u64 sph_dec64le_aligned(const void *src);

/**
 * Encode a 64-bit unsigned value into memory, in little-endian convention
 * (least significant byte comes first). This function is defined only
 * if a suitable 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc64le(void *dst, sph_u64 val);

/**
 * Encode a 64-bit unsigned value into memory, in little-endian convention
 * (least significant byte comes first). This function assumes that the
 * destination address is suitably aligned for a direct access, if the
 * platform supports such things; it can thus be marginally faster than
 * the generic <code>sph_enc64le()</code> function. This function is defined
 * only if a suitable 64-bit type was detected and used for
 * <code>sph_u64</code>.
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc64le_aligned(void *dst, sph_u64 val);

/**
 * Decode a 64-bit unsigned value from memory, in big-endian convention
 * (most significant byte comes first). This function is defined only
 * if a suitable 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u64 sph_dec64be(const void *src);

/**
 * Decode a 64-bit unsigned value from memory, in big-endian convention
 * (most significant byte comes first). This function assumes that the
 * source address is suitably aligned for a direct access, if the platform
 * supports such things; it can thus be marginally faster than the generic
 * <code>sph_dec64be()</code> function. This function is defined only
 * if a suitable 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param src   the source address
 * @return  the decoded value
 */
static inline sph_u64 sph_dec64be_aligned(const void *src);

/**
 * Encode a 64-bit unsigned value into memory, in big-endian convention
 * (most significant byte comes first). This function is defined only
 * if a suitable 64-bit type was detected and used for <code>sph_u64</code>.
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc64be(void *dst, sph_u64 val);

/**
 * Encode a 64-bit unsigned value into memory, in big-endian convention
 * (most significant byte comes first). This function assumes that the
 * destination address is suitably aligned for a direct access, if the
 * platform supports such things; it can thus be marginally faster than
 * the generic <code>sph_enc64be()</code> function. This function is defined
 * only if a suitable 64-bit type was detected and used for
 * <code>sph_u64</code>.
 *
 * @param dst   the destination buffer
 * @param val   the value to encode
 */
static inline void sph_enc64be_aligned(void *dst, sph_u64 val);

#endif

/* ============== END documentation block for Doxygen ============= */

#ifndef DOXYGEN_IGNORE

/*
 * We want to define the types "sph_u32" and "sph_u64" which hold
 * unsigned values of at least, respectively, 32 and 64 bits. These
 * tests should select appropriate types for most platforms. The
 * macro "SPH_64" is defined if the 64-bit is supported.
 */

#undef SPH_64
#undef SPH_64_TRUE

#if defined __STDC__ && __STDC_VERSION__ >= 199901L

/*
 * On C99 implementations, we can use <stdint.h> to get an exact 64-bit
 * type, if any, or otherwise use a wider type (which must exist, for
 * C99 conformance).
 */

#include <stdint.h>

#ifdef UINT32_MAX
typedef uint32_t sph_u32;
typedef int32_t sph_s32;
#else
typedef uint_fast32_t sph_u32;
typedef int_fast32_t sph_s32;
#endif
#if !SPH_NO_64
#ifdef UINT64_MAX
typedef uint64_t sph_u64;
typedef int64_t sph_s64;
#else
typedef uint_fast64_t sph_u64;
typedef int_fast64_t sph_s64;
#endif
#endif

#define SPH_C32(x)    ((sph_u32)(x))
#if !SPH_NO_64
#define SPH_C64(x)    ((sph_u64)(x))
#define SPH_64  1
#endif

#else

/*
 * On non-C99 systems, we use "unsigned int" if it is wide enough,
 * "unsigned long" otherwise. This supports all "reasonable" architectures.
 * We have to be cautious: pre-C99 preprocessors handle constants
 * differently in '#if' expressions. Hence the shifts to test UINT_MAX.
 */

#if ((UINT_MAX >> 11) >> 11) >= 0x3FF

typedef unsigned int sph_u32;
typedef int sph_s32;

#define SPH_C32(x)    ((sph_u32)(x ## U))

#else

typedef unsigned long sph_u32;
typedef long sph_s32;

#define SPH_C32(x)    ((sph_u32)(x ## UL))

#endif

#if !SPH_NO_64

/*
 * We want a 64-bit type. We use "unsigned long" if it is wide enough (as
 * is common on 64-bit architectures such as AMD64, Alpha or Sparcv9),
 * "unsigned long long" otherwise, if available. We use ULLONG_MAX to
 * test whether "unsigned long long" is available; we also know that
 * gcc features this type, even if the libc header do not know it.
 */

#if ((ULONG_MAX >> 31) >> 31) >= 3

typedef unsigned long sph_u64;
typedef long sph_s64;

#define SPH_C64(x)    ((sph_u64)(x ## UL))

#define SPH_64  1

#elif ((ULLONG_MAX >> 31) >> 31) >= 3 || defined __GNUC__

typedef unsigned long long sph_u64;
typedef long long sph_s64;

#define SPH_C64(x)    ((sph_u64)(x ## ULL))

#define SPH_64  1

#else

/*
 * No 64-bit type...
 */

#endif

#endif

#endif

/*
 * If the "unsigned long" type has length 64 bits or more, then this is
 * a "true" 64-bit architectures. This is also true with Visual C on
 * amd64, even though the "long" type is limited to 32 bits.
 */
#if SPH_64 && (((ULONG_MAX >> 31) >> 31) >= 3 || defined _M_X64)
#define SPH_64_TRUE   1
#endif

/*
 * Implementation note: some processors have specific opcodes to perform
 * a rotation. Recent versions of gcc recognize the expression above and
 * use the relevant opcodes, when appropriate.
 */

#define SPH_T32(x)    ((x) & SPH_C32(0xFFFFFFFF))
#define SPH_ROTL32(x, n)   SPH_T32(((x) << (n)) | ((x) >> (32 - (n))))
#define SPH_ROTR32(x, n)   SPH_ROTL32(x, (32 - (n)))

#if SPH_64

#define SPH_T64(x)    ((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))
#define SPH_ROTL64(x, n)   SPH_T64(((x) << (n)) | ((x) >> (64 - (n))))
#define SPH_ROTR64(x, n)   SPH_ROTL64(x, (64 - (n)))

#endif

#ifndef DOXYGEN_IGNORE
/*
 * Define SPH_INLINE to be an "inline" qualifier, if available. We define
 * some small macro-like functions which benefit greatly from being inlined.
 */
#if (defined __STDC__ && __STDC_VERSION__ >= 199901L) || defined __GNUC__
#define SPH_INLINE inline
#elif defined _MSC_VER
#define SPH_INLINE __inline
#else
#define SPH_INLINE
#endif
#endif

/*
 * We define some macros which qualify the architecture. These macros
 * may be explicit set externally (e.g. as compiler parameters). The
 * code below sets those macros if they are not already defined.
 *
 * Most macros are boolean, thus evaluate to either zero or non-zero.
 * The SPH_UPTR macro is special, in that it evaluates to a C type,
 * or is not defined.
 *
 * SPH_UPTR             if defined: unsigned type to cast pointers into
 *
 * SPH_UNALIGNED        non-zero if unaligned accesses are efficient
 * SPH_LITTLE_ENDIAN    non-zero if architecture is known to be little-endian
 * SPH_BIG_ENDIAN       non-zero if architecture is known to be big-endian
 * SPH_LITTLE_FAST      non-zero if little-endian decoding is fast
 * SPH_BIG_FAST         non-zero if big-endian decoding is fast
 *
 * If SPH_UPTR is defined, then encoding and decoding of 32-bit and 64-bit
 * values will try to be "smart". Either SPH_LITTLE_ENDIAN or SPH_BIG_ENDIAN
 * _must_ be non-zero in those situations. The 32-bit and 64-bit types
 * _must_ also have an exact width.
 *
 * SPH_SPARCV9_GCC_32   UltraSPARC-compatible with gcc, 32-bit mode
 * SPH_SPARCV9_GCC_64   UltraSPARC-compatible with gcc, 64-bit mode
 * SPH_SPARCV9_GCC      UltraSPARC-compatible with gcc
 * SPH_I386_GCC         x86-compatible (32-bit) with gcc
 * SPH_I386_MSVC        x86-compatible (32-bit) with Microsoft Visual C
 * SPH_AMD64_GCC        x86-compatible (64-bit) with gcc
 * SPH_AMD64_MSVC       x86-compatible (64-bit) with Microsoft Visual C
 * SPH_PPC32_GCC        PowerPC, 32-bit, with gcc
 * SPH_PPC64_GCC        PowerPC, 64-bit, with gcc
 *
 * TODO: enhance automatic detection, for more architectures and compilers.
 * Endianness is the most important. SPH_UNALIGNED and SPH_UPTR help with
 * some very fast functions (e.g. MD4) when using unaligned input data.
 * The CPU-specific-with-GCC macros are useful only for inline assembly,
 * normally restrained to this header file.
 */

/*
 * 32-bit x86, aka "i386 compatible".
 */
#if defined __i386__ || defined _M_IX86

#define SPH_DETECT_UNALIGNED         1
#define SPH_DETECT_LITTLE_ENDIAN     1
#define SPH_DETECT_UPTR              sph_u32
#ifdef __GNUC__
#define SPH_DETECT_I386_GCC          1
#endif
#ifdef _MSC_VER
#define SPH_DETECT_I386_MSVC         1
#endif

/*
 * 64-bit x86, hereafter known as "amd64".
 */
#elif defined __x86_64 || defined _M_X64

#define SPH_DETECT_UNALIGNED         1
#define SPH_DETECT_LITTLE_ENDIAN     1
#define SPH_DETECT_UPTR              sph_u64
#ifdef __GNUC__
#define SPH_DETECT_AMD64_GCC         1
#endif
#ifdef _MSC_VER
#define SPH_DETECT_AMD64_MSVC        1
#endif

/*
 * 64-bit Sparc architecture (implies v9).
 */
#elif ((defined __sparc__ || defined __sparc) && defined __arch64__) \
	|| defined __sparcv9

#define SPH_DETECT_BIG_ENDIAN        1
#define SPH_DETECT_UPTR              sph_u64
#ifdef __GNUC__
#define SPH_DETECT_SPARCV9_GCC_64    1
#define SPH_DETECT_LITTLE_FAST       1
#endif

/*
 * 32-bit Sparc.
 */
#elif (defined __sparc__ || defined __sparc) \
	&& !(defined __sparcv9 || defined __arch64__)

#define SPH_DETECT_BIG_ENDIAN        1
#define SPH_DETECT_UPTR              sph_u32
#if defined __GNUC__ && defined __sparc_v9__
#define SPH_DETECT_SPARCV9_GCC_32    1
#define SPH_DETECT_LITTLE_FAST       1
#endif

/*
 * ARM, little-endian.
 */
#elif defined __arm__ && __ARMEL__

#define SPH_DETECT_LITTLE_ENDIAN     1

/*
 * MIPS, little-endian.
 */
#elif MIPSEL || _MIPSEL || __MIPSEL || __MIPSEL__

#define SPH_DETECT_LITTLE_ENDIAN     1

/*
 * MIPS, big-endian.
 */
#elif MIPSEB || _MIPSEB || __MIPSEB || __MIPSEB__

#define SPH_DETECT_BIG_ENDIAN        1

/*
 * PowerPC.
 */
#elif defined __powerpc__ || defined __POWERPC__ || defined __ppc__ \
	|| defined _ARCH_PPC

/*
 * Note: we do not declare cross-endian access to be "fast": even if
 * using inline assembly, implementation should still assume that
 * keeping the decoded word in a temporary is faster than decoding
 * it again.
 */
#if defined __GNUC__
#if SPH_64_TRUE
#define SPH_DETECT_PPC64_GCC         1
#else
#define SPH_DETECT_PPC32_GCC         1
#endif
#endif

#if defined __BIG_ENDIAN__ || defined _BIG_ENDIAN
#define SPH_DETECT_BIG_ENDIAN        1
#elif defined __LITTLE_ENDIAN__ || defined _LITTLE_ENDIAN
#define SPH_DETECT_LITTLE_ENDIAN     1
#endif

/*
 * Itanium, 64-bit.
 */
#elif defined __ia64 || defined __ia64__ \
	|| defined __itanium__ || defined _M_IA64

#if defined __BIG_ENDIAN__ || defined _BIG_ENDIAN
#define SPH_DETECT_BIG_ENDIAN        1
#else
#define SPH_DETECT_LITTLE_ENDIAN     1
#endif
#if defined __LP64__ || defined _LP64
#define SPH_DETECT_UPTR              sph_u64
#else
#define SPH_DETECT_UPTR              sph_u32
#endif

#endif

#if defined SPH_DETECT_SPARCV9_GCC_32 || defined SPH_DETECT_SPARCV9_GCC_64
#define SPH_DETECT_SPARCV9_GCC       1
#endif

#if defined SPH_DETECT_UNALIGNED && !defined SPH_UNALIGNED
#define SPH_UNALIGNED         SPH_DETECT_UNALIGNED
#endif
#if defined SPH_DETECT_UPTR && !defined SPH_UPTR
#define SPH_UPTR              SPH_DETECT_UPTR
#endif
#if defined SPH_DETECT_LITTLE_ENDIAN && !defined SPH_LITTLE_ENDIAN
#define SPH_LITTLE_ENDIAN     SPH_DETECT_LITTLE_ENDIAN
#endif
#if defined SPH_DETECT_BIG_ENDIAN && !defined SPH_BIG_ENDIAN
#define SPH_BIG_ENDIAN        SPH_DETECT_BIG_ENDIAN
#endif
#if defined SPH_DETECT_LITTLE_FAST && !defined SPH_LITTLE_FAST
#define SPH_LITTLE_FAST       SPH_DETECT_LITTLE_FAST
#endif
#if defined SPH_DETECT_BIG_FAST && !defined SPH_BIG_FAST
#define SPH_BIG_FAST    SPH_DETECT_BIG_FAST
#endif
#if defined SPH_DETECT_SPARCV9_GCC_32 && !defined SPH_SPARCV9_GCC_32
#define SPH_SPARCV9_GCC_32    SPH_DETECT_SPARCV9_GCC_32
#endif
#if defined SPH_DETECT_SPARCV9_GCC_64 && !defined SPH_SPARCV9_GCC_64
#define SPH_SPARCV9_GCC_64    SPH_DETECT_SPARCV9_GCC_64
#endif
#if defined SPH_DETECT_SPARCV9_GCC && !defined SPH_SPARCV9_GCC
#define SPH_SPARCV9_GCC       SPH_DETECT_SPARCV9_GCC
#endif
#if defined SPH_DETECT_I386_GCC && !defined SPH_I386_GCC
#define SPH_I386_GCC          SPH_DETECT_I386_GCC
#endif
#if defined SPH_DETECT_I386_MSVC && !defined SPH_I386_MSVC
#define SPH_I386_MSVC         SPH_DETECT_I386_MSVC
#endif
#if defined SPH_DETECT_AMD64_GCC && !defined SPH_AMD64_GCC
#define SPH_AMD64_GCC         SPH_DETECT_AMD64_GCC
#endif
#if defined SPH_DETECT_AMD64_MSVC && !defined SPH_AMD64_MSVC
#define SPH_AMD64_MSVC        SPH_DETECT_AMD64_MSVC
#endif
#if defined SPH_DETECT_PPC32_GCC && !defined SPH_PPC32_GCC
#define SPH_PPC32_GCC         SPH_DETECT_PPC32_GCC
#endif
#if defined SPH_DETECT_PPC64_GCC && !defined SPH_PPC64_GCC
#define SPH_PPC64_GCC         SPH_DETECT_PPC64_GCC
#endif

#if SPH_LITTLE_ENDIAN && !defined SPH_LITTLE_FAST
#define SPH_LITTLE_FAST              1
#endif
#if SPH_BIG_ENDIAN && !defined SPH_BIG_FAST
#define SPH_BIG_FAST                 1
#endif

#if defined SPH_UPTR && !(SPH_LITTLE_ENDIAN || SPH_BIG_ENDIAN)
#error SPH_UPTR defined, but endianness is not known.
#endif

#if SPH_I386_GCC && !SPH_NO_ASM

/*
 * On x86 32-bit, with gcc, we use the bswapl opcode to byte-swap 32-bit
 * values.
 */

static SPH_INLINE sph_u32
sph_bswap32(sph_u32 x)
{
	__asm__ __volatile__ ("bswapl %0" : "=r" (x) : "0" (x));
	return x;
}

#if SPH_64

static SPH_INLINE sph_u64
sph_bswap64(sph_u64 x)
{
	return ((sph_u64)sph_bswap32((sph_u32)x) << 32)
		| (sph_u64)sph_bswap32((sph_u32)(x >> 32));
}

#endif

#elif SPH_AMD64_GCC && !SPH_NO_ASM

/*
 * On x86 64-bit, with gcc, we use the bswapl opcode to byte-swap 32-bit
 * and 64-bit values.
 */

static SPH_INLINE sph_u32
sph_bswap32(sph_u32 x)
{
	__asm__ __volatile__ ("bswapl %0" : "=r" (x) : "0" (x));
	return x;
}

#if SPH_64

static SPH_INLINE sph_u64
sph_bswap64(sph_u64 x)
{
	__asm__ __volatile__ ("bswapq %0" : "=r" (x) : "0" (x));
	return x;
}

#endif

/*
 * Disabled code. Apparently, Microsoft Visual C 2005 is smart enough
 * to generate proper opcodes for endianness swapping with the pure C
 * implementation below.
 *

#elif SPH_I386_MSVC && !SPH_NO_ASM

static __inline sph_u32 __declspec(naked) __fastcall
sph_bswap32(sph_u32 x)
{
	__asm {
		bswap  ecx
		mov    eax,ecx
		ret
	}
}

#if SPH_64

static SPH_INLINE sph_u64
sph_bswap64(sph_u64 x)
{
	return ((sph_u64)sph_bswap32((sph_u32)x) << 32)
		| (sph_u64)sph_bswap32((sph_u32)(x >> 32));
}

#endif

 *
 * [end of disabled code]
 */

#else

static SPH_INLINE sph_u32
sph_bswap32(sph_u32 x)
{
	x = SPH_T32((x << 16) | (x >> 16));
	x = ((x & SPH_C32(0xFF00FF00)) >> 8)
		| ((x & SPH_C32(0x00FF00FF)) << 8);
	return x;
}

#if SPH_64

/**
 * Byte-swap a 64-bit value.
 *
 * @param x   the input value
 * @return  the byte-swapped value
 */
static SPH_INLINE sph_u64
sph_bswap64(sph_u64 x)
{
	x = SPH_T64((x << 32) | (x >> 32));
	x = ((x & SPH_C64(0xFFFF0000FFFF0000)) >> 16)
		| ((x & SPH_C64(0x0000FFFF0000FFFF)) << 16);
	x = ((x & SPH_C64(0xFF00FF00FF00FF00)) >> 8)
		| ((x & SPH_C64(0x00FF00FF00FF00FF)) << 8);
	return x;
}

#endif

#endif

#if SPH_SPARCV9_GCC && !SPH_NO_ASM

/*
 * On UltraSPARC systems, native ordering is big-endian, but it is
 * possible to perform little-endian read accesses by specifying the
 * address space 0x88 (ASI_PRIMARY_LITTLE). Basically, either we use
 * the opcode "lda [%reg]0x88,%dst", where %reg is the register which
 * contains the source address and %dst is the destination register,
 * or we use "lda [%reg+imm]%asi,%dst", which uses the %asi register
 * to get the address space name. The latter format is better since it
 * combines an addition and the actual access in a single opcode; but
 * it requires the setting (and subsequent resetting) of %asi, which is
 * slow. Some operations (i.e. MD5 compression function) combine many
 * successive little-endian read accesses, which may share the same
 * %asi setting. The macros below contain the appropriate inline
 * assembly.
 */

#define SPH_SPARCV9_SET_ASI   \
	sph_u32 sph_sparcv9_asi; \
	__asm__ __volatile__ ( \
		"rd %%asi,%0\n\twr %%g0,0x88,%%asi" : "=r" (sph_sparcv9_asi));

#define SPH_SPARCV9_RESET_ASI  \
	__asm__ __volatile__ ("wr %%g0,%0,%%asi" : : "r" (sph_sparcv9_asi));

#define SPH_SPARCV9_DEC32LE(base, idx)   ({ \
		sph_u32 sph_sparcv9_tmp; \
		__asm__ __volatile__ ("lda [%1+" #idx "*4]%%asi,%0" \
			: "=r" (sph_sparcv9_tmp) : "r" (base)); \
		sph_sparcv9_tmp; \
	})

#endif

static SPH_INLINE void
sph_enc16be(void *dst, unsigned val)
{
	((unsigned char *)dst)[0] = (val >> 8);
	((unsigned char *)dst)[1] = val;
}

static SPH_INLINE unsigned
sph_dec16be(const void *src)
{
	return ((unsigned)(((const unsigned char *)src)[0]) << 8)
		| (unsigned)(((const unsigned char *)src)[1]);
}

static SPH_INLINE void
sph_enc16le(void *dst, unsigned val)
{
	((unsigned char *)dst)[0] = val;
	((unsigned char *)dst)[1] = val >> 8;
}

static SPH_INLINE unsigned
sph_dec16le(const void *src)
{
	return (unsigned)(((const unsigned char *)src)[0])
		| ((unsigned)(((const unsigned char *)src)[1]) << 8);
}

/**
 * Encode a 32-bit value into the provided buffer (big endian convention).
 *
 * @param dst   the destination buffer
 * @param val   the 32-bit value to encode
 */
static SPH_INLINE void
sph_enc32be(void *dst, sph_u32 val)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_LITTLE_ENDIAN
	val = sph_bswap32(val);
#endif
	*(sph_u32 *)dst = val;
#else
	if (((SPH_UPTR)dst & 3) == 0) {
#if SPH_LITTLE_ENDIAN
		val = sph_bswap32(val);
#endif
		*(sph_u32 *)dst = val;
	} else {
		((unsigned char *)dst)[0] = (val >> 24);
		((unsigned char *)dst)[1] = (val >> 16);
		((unsigned char *)dst)[2] = (val >> 8);
		((unsigned char *)dst)[3] = val;
	}
#endif
#else
	((unsigned char *)dst)[0] = (val >> 24);
	((unsigned char *)dst)[1] = (val >> 16);
	((unsigned char *)dst)[2] = (val >> 8);
	((unsigned char *)dst)[3] = val;
#endif
}

/**
 * Encode a 32-bit value into the provided buffer (big endian convention).
 * The destination buffer must be properly aligned.
 *
 * @param dst   the destination buffer (32-bit aligned)
 * @param val   the value to encode
 */
static SPH_INLINE void
sph_enc32be_aligned(void *dst, sph_u32 val)
{
#if SPH_LITTLE_ENDIAN
	*(sph_u32 *)dst = sph_bswap32(val);
#elif SPH_BIG_ENDIAN
	*(sph_u32 *)dst = val;
#else
	((unsigned char *)dst)[0] = (val >> 24);
	((unsigned char *)dst)[1] = (val >> 16);
	((unsigned char *)dst)[2] = (val >> 8);
	((unsigned char *)dst)[3] = val;
#endif
}

/**
 * Decode a 32-bit value from the provided buffer (big endian convention).
 *
 * @param src   the source buffer
 * @return  the decoded value
 */
static SPH_INLINE sph_u32
sph_dec32be(const void *src)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_LITTLE_ENDIAN
	return sph_bswap32(*(const sph_u32 *)src);
#else
	return *(const sph_u32 *)src;
#endif
#else
	if (((SPH_UPTR)src & 3) == 0) {
#if SPH_LITTLE_ENDIAN
		return sph_bswap32(*(const sph_u32 *)src);
#else
		return *(const sph_u32 *)src;
#endif
	} else {
		return ((sph_u32)(((const unsigned char *)src)[0]) << 24)
			| ((sph_u32)(((const unsigned char *)src)[1]) << 16)
			| ((sph_u32)(((const unsigned char *)src)[2]) << 8)
			| (sph_u32)(((const unsigned char *)src)[3]);
	}
#endif
#else
	return ((sph_u32)(((const unsigned char *)src)[0]) << 24)
		| ((sph_u32)(((const unsigned char *)src)[1]) << 16)
		| ((sph_u32)(((const unsigned char *)src)[2]) << 8)
		| (sph_u32)(((const unsigned char *)src)[3]);
#endif
}

/**
 * Decode a 32-bit value from the provided buffer (big endian convention).
 * The source buffer must be properly aligned.
 *
 * @param src   the source buffer (32-bit aligned)
 * @return  the decoded value
 */
static SPH_INLINE sph_u32
sph_dec32be_aligned(const void *src)
{
#if SPH_LITTLE_ENDIAN
	return sph_bswap32(*(const sph_u32 *)src);
#elif SPH_BIG_ENDIAN
	return *(const sph_u32 *)src;
#else
	return ((sph_u32)(((const unsigned char *)src)[0]) << 24)
		| ((sph_u32)(((const unsigned char *)src)[1]) << 16)
		| ((sph_u32)(((const unsigned char *)src)[2]) << 8)
		| (sph_u32)(((const unsigned char *)src)[3]);
#endif
}

/**
 * Encode a 32-bit value into the provided buffer (little endian convention).
 *
 * @param dst   the destination buffer
 * @param val   the 32-bit value to encode
 */
static SPH_INLINE void
sph_enc32le(void *dst, sph_u32 val)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_BIG_ENDIAN
	val = sph_bswap32(val);
#endif
	*(sph_u32 *)dst = val;
#else
	if (((SPH_UPTR)dst & 3) == 0) {
#if SPH_BIG_ENDIAN
		val = sph_bswap32(val);
#endif
		*(sph_u32 *)dst = val;
	} else {
		((unsigned char *)dst)[0] = val;
		((unsigned char *)dst)[1] = (val >> 8);
		((unsigned char *)dst)[2] = (val >> 16);
		((unsigned char *)dst)[3] = (val >> 24);
	}
#endif
#else
	((unsigned char *)dst)[0] = val;
	((unsigned char *)dst)[1] = (val >> 8);
	((unsigned char *)dst)[2] = (val >> 16);
	((unsigned char *)dst)[3] = (val >> 24);
#endif
}

/**
 * Encode a 32-bit value into the provided buffer (little endian convention).
 * The destination buffer must be properly aligned.
 *
 * @param dst   the destination buffer (32-bit aligned)
 * @param val   the value to encode
 */
static SPH_INLINE void
sph_enc32le_aligned(void *dst, sph_u32 val)
{
#if SPH_LITTLE_ENDIAN
	*(sph_u32 *)dst = val;
#elif SPH_BIG_ENDIAN
	*(sph_u32 *)dst = sph_bswap32(val);
#else
	((unsigned char *)dst)[0] = val;
	((unsigned char *)dst)[1] = (val >> 8);
	((unsigned char *)dst)[2] = (val >> 16);
	((unsigned char *)dst)[3] = (val >> 24);
#endif
}

/**
 * Decode a 32-bit value from the provided buffer (little endian convention).
 *
 * @param src   the source buffer
 * @return  the decoded value
 */
static SPH_INLINE sph_u32
sph_dec32le(const void *src)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_BIG_ENDIAN
	return sph_bswap32(*(const sph_u32 *)src);
#else
	return *(const sph_u32 *)src;
#endif
#else
	if (((SPH_UPTR)src & 3) == 0) {
#if SPH_BIG_ENDIAN
#if SPH_SPARCV9_GCC && !SPH_NO_ASM
		sph_u32 tmp;

		/*
		 * "__volatile__" is needed here because without it,
		 * gcc-3.4.3 miscompiles the code and performs the
		 * access before the test on the address, thus triggering
		 * a bus error...
		 */
		__asm__ __volatile__ (
			"lda [%1]0x88,%0" : "=r" (tmp) : "r" (src));
		return tmp;
/*
 * On PowerPC, this turns out not to be worth the effort: the inline
 * assembly makes GCC optimizer uncomfortable, which tends to nullify
 * the decoding gains.
 *
 * For most hash functions, using this inline assembly trick changes
 * hashing speed by less than 5% and often _reduces_ it. The biggest
 * gains are for MD4 (+11%) and CubeHash (+30%). For all others, it is
 * less then 10%. The speed gain on CubeHash is probably due to the
 * chronic shortage of registers that CubeHash endures; for the other
 * functions, the generic code appears to be efficient enough already.
 *
#elif (SPH_PPC32_GCC || SPH_PPC64_GCC) && !SPH_NO_ASM
		sph_u32 tmp;

		__asm__ __volatile__ (
			"lwbrx %0,0,%1" : "=r" (tmp) : "r" (src));
		return tmp;
 */
#else
		return sph_bswap32(*(const sph_u32 *)src);
#endif
#else
		return *(const sph_u32 *)src;
#endif
	} else {
		return (sph_u32)(((const unsigned char *)src)[0])
			| ((sph_u32)(((const unsigned char *)src)[1]) << 8)
			| ((sph_u32)(((const unsigned char *)src)[2]) << 16)
			| ((sph_u32)(((const unsigned char *)src)[3]) << 24);
	}
#endif
#else
	return (sph_u32)(((const unsigned char *)src)[0])
		| ((sph_u32)(((const unsigned char *)src)[1]) << 8)
		| ((sph_u32)(((const unsigned char *)src)[2]) << 16)
		| ((sph_u32)(((const unsigned char *)src)[3]) << 24);
#endif
}

/**
 * Decode a 32-bit value from the provided buffer (little endian convention).
 * The source buffer must be properly aligned.
 *
 * @param src   the source buffer (32-bit aligned)
 * @return  the decoded value
 */
static SPH_INLINE sph_u32
sph_dec32le_aligned(const void *src)
{
#if SPH_LITTLE_ENDIAN
	return *(const sph_u32 *)src;
#elif SPH_BIG_ENDIAN
#if SPH_SPARCV9_GCC && !SPH_NO_ASM
	sph_u32 tmp;

	__asm__ __volatile__ ("lda [%1]0x88,%0" : "=r" (tmp) : "r" (src));
	return tmp;
/*
 * Not worth it generally.
 *
#elif (SPH_PPC32_GCC || SPH_PPC64_GCC) && !SPH_NO_ASM
	sph_u32 tmp;

	__asm__ __volatile__ ("lwbrx %0,0,%1" : "=r" (tmp) : "r" (src));
	return tmp;
 */
#else
	return sph_bswap32(*(const sph_u32 *)src);
#endif
#else
	return (sph_u32)(((const unsigned char *)src)[0])
		| ((sph_u32)(((const unsigned char *)src)[1]) << 8)
		| ((sph_u32)(((const unsigned char *)src)[2]) << 16)
		| ((sph_u32)(((const unsigned char *)src)[3]) << 24);
#endif
}

#if SPH_64

/**
 * Encode a 64-bit value into the provided buffer (big endian convention).
 *
 * @param dst   the destination buffer
 * @param val   the 64-bit value to encode
 */
static SPH_INLINE void
sph_enc64be(void *dst, sph_u64 val)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_LITTLE_ENDIAN
	val = sph_bswap64(val);
#endif
	*(sph_u64 *)dst = val;
#else
	if (((SPH_UPTR)dst & 7) == 0) {
#if SPH_LITTLE_ENDIAN
		val = sph_bswap64(val);
#endif
		*(sph_u64 *)dst = val;
	} else {
		((unsigned char *)dst)[0] = (val >> 56);
		((unsigned char *)dst)[1] = (val >> 48);
		((unsigned char *)dst)[2] = (val >> 40);
		((unsigned char *)dst)[3] = (val >> 32);
		((unsigned char *)dst)[4] = (val >> 24);
		((unsigned char *)dst)[5] = (val >> 16);
		((unsigned char *)dst)[6] = (val >> 8);
		((unsigned char *)dst)[7] = val;
	}
#endif
#else
	((unsigned char *)dst)[0] = (val >> 56);
	((unsigned char *)dst)[1] = (val >> 48);
	((unsigned char *)dst)[2] = (val >> 40);
	((unsigned char *)dst)[3] = (val >> 32);
	((unsigned char *)dst)[4] = (val >> 24);
	((unsigned char *)dst)[5] = (val >> 16);
	((unsigned char *)dst)[6] = (val >> 8);
	((unsigned char *)dst)[7] = val;
#endif
}

/**
 * Encode a 64-bit value into the provided buffer (big endian convention).
 * The destination buffer must be properly aligned.
 *
 * @param dst   the destination buffer (64-bit aligned)
 * @param val   the value to encode
 */
static SPH_INLINE void
sph_enc64be_aligned(void *dst, sph_u64 val)
{
#if SPH_LITTLE_ENDIAN
	*(sph_u64 *)dst = sph_bswap64(val);
#elif SPH_BIG_ENDIAN
	*(sph_u64 *)dst = val;
#else
	((unsigned char *)dst)[0] = (val >> 56);
	((unsigned char *)dst)[1] = (val >> 48);
	((unsigned char *)dst)[2] = (val >> 40);
	((unsigned char *)dst)[3] = (val >> 32);
	((unsigned char *)dst)[4] = (val >> 24);
	((unsigned char *)dst)[5] = (val >> 16);
	((unsigned char *)dst)[6] = (val >> 8);
	((unsigned char *)dst)[7] = val;
#endif
}

/**
 * Decode a 64-bit value from the provided buffer (big endian convention).
 *
 * @param src   the source buffer
 * @return  the decoded value
 */
static SPH_INLINE sph_u64
sph_dec64be(const void *src)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_LITTLE_ENDIAN
	return sph_bswap64(*(const sph_u64 *)src);
#else
	return *(const sph_u64 *)src;
#endif
#else
	if (((SPH_UPTR)src & 7) == 0) {
#if SPH_LITTLE_ENDIAN
		return sph_bswap64(*(const sph_u64 *)src);
#else
		return *(const sph_u64 *)src;
#endif
	} else {
		return ((sph_u64)(((const unsigned char *)src)[0]) << 56)
			| ((sph_u64)(((const unsigned char *)src)[1]) << 48)
			| ((sph_u64)(((const unsigned char *)src)[2]) << 40)
			| ((sph_u64)(((const unsigned char *)src)[3]) << 32)
			| ((sph_u64)(((const unsigned char *)src)[4]) << 24)
			| ((sph_u64)(((const unsigned char *)src)[5]) << 16)
			| ((sph_u64)(((const unsigned char *)src)[6]) << 8)
			| (sph_u64)(((const unsigned char *)src)[7]);
	}
#endif
#else
	return ((sph_u64)(((const unsigned char *)src)[0]) << 56)
		| ((sph_u64)(((const unsigned char *)src)[1]) << 48)
		| ((sph_u64)(((const unsigned char *)src)[2]) << 40)
		| ((sph_u64)(((const unsigned char *)src)[3]) << 32)
		| ((sph_u64)(((const unsigned char *)src)[4]) << 24)
		| ((sph_u64)(((const unsigned char *)src)[5]) << 16)
		| ((sph_u64)(((const unsigned char *)src)[6]) << 8)
		| (sph_u64)(((const unsigned char *)src)[7]);
#endif
}

/**
 * Decode a 64-bit value from the provided buffer (big endian convention).
 * The source buffer must be properly aligned.
 *
 * @param src   the source buffer (64-bit aligned)
 * @return  the decoded value
 */
static SPH_INLINE sph_u64
sph_dec64be_aligned(const void *src)
{
#if SPH_LITTLE_ENDIAN
	return sph_bswap64(*(const sph_u64 *)src);
#elif SPH_BIG_ENDIAN
	return *(const sph_u64 *)src;
#else
	return ((sph_u64)(((const unsigned char *)src)[0]) << 56)
		| ((sph_u64)(((const unsigned char *)src)[1]) << 48)
		| ((sph_u64)(((const unsigned char *)src)[2]) << 40)
		| ((sph_u64)(((const unsigned char *)src)[3]) << 32)
		| ((sph_u64)(((const unsigned char *)src)[4]) << 24)
		| ((sph_u64)(((const unsigned char *)src)[5]) << 16)
		| ((sph_u64)(((const unsigned char *)src)[6]) << 8)
		| (sph_u64)(((const unsigned char *)src)[7]);
#endif
}

/**
 * Encode a 64-bit value into the provided buffer (little endian convention).
 *
 * @param dst   the destination buffer
 * @param val   the 64-bit value to encode
 */
static SPH_INLINE void
sph_enc64le(void *dst, sph_u64 val)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_BIG_ENDIAN
	val = sph_bswap64(val);
#endif
	*(sph_u64 *)dst = val;
#else
	if (((SPH_UPTR)dst & 7) == 0) {
#if SPH_BIG_ENDIAN
		val = sph_bswap64(val);
#endif
		*(sph_u64 *)dst = val;
	} else {
		((unsigned char *)dst)[0] = val;
		((unsigned char *)dst)[1] = (val >> 8);
		((unsigned char *)dst)[2] = (val >> 16);
		((unsigned char *)dst)[3] = (val >> 24);
		((unsigned char *)dst)[4] = (val >> 32);
		((unsigned char *)dst)[5] = (val >> 40);
		((unsigned char *)dst)[6] = (val >> 48);
		((unsigned char *)dst)[7] = (val >> 56);
	}
#endif
#else
	((unsigned char *)dst)[0] = val;
	((unsigned char *)dst)[1] = (val >> 8);
	((unsigned char *)dst)[2] = (val >> 16);
	((unsigned char *)dst)[3] = (val >> 24);
	((unsigned char *)dst)[4] = (val >> 32);
	((unsigned char *)dst)[5] = (val >> 40);
	((unsigned char *)dst)[6] = (val >> 48);
	((unsigned char *)dst)[7] = (val >> 56);
#endif
}

/**
 * Encode a 64-bit value into the provided buffer (little endian convention).
 * The destination buffer must be properly aligned.
 *
 * @param dst   the destination buffer (64-bit aligned)
 * @param val   the value to encode
 */
static SPH_INLINE void
sph_enc64le_aligned(void *dst, sph_u64 val)
{
#if SPH_LITTLE_ENDIAN
	*(sph_u64 *)dst = val;
#elif SPH_BIG_ENDIAN
	*(sph_u64 *)dst = sph_bswap64(val);
#else
	((unsigned char *)dst)[0] = val;
	((unsigned char *)dst)[1] = (val >> 8);
	((unsigned char *)dst)[2] = (val >> 16);
	((unsigned char *)dst)[3] = (val >> 24);
	((unsigned char *)dst)[4] = (val >> 32);
	((unsigned char *)dst)[5] = (val >> 40);
	((unsigned char *)dst)[6] = (val >> 48);
	((unsigned char *)dst)[7] = (val >> 56);
#endif
}

/**
 * Decode a 64-bit value from the provided buffer (little endian convention).
 *
 * @param src   the source buffer
 * @return  the decoded value
 */
static SPH_INLINE sph_u64
sph_dec64le(const void *src)
{
#if defined SPH_UPTR
#if SPH_UNALIGNED
#if SPH_BIG_ENDIAN
	return sph_bswap64(*(const sph_u64 *)src);
#else
	return *(const sph_u64 *)src;
#endif
#else
	if (((SPH_UPTR)src & 7) == 0) {
#if SPH_BIG_ENDIAN
#if SPH_SPARCV9_GCC_64 && !SPH_NO_ASM
		sph_u64 tmp;

		__asm__ __volatile__ (
			"ldxa [%1]0x88,%0" : "=r" (tmp) : "r" (src));
		return tmp;
/*
 * Not worth it generally.
 *
#elif SPH_PPC32_GCC && !SPH_NO_ASM
		return (sph_u64)sph_dec32le_aligned(src)
			| ((sph_u64)sph_dec32le_aligned(
				(const char *)src + 4) << 32);
#elif SPH_PPC64_GCC && !SPH_NO_ASM
		sph_u64 tmp;

		__asm__ __volatile__ (
			"ldbrx %0,0,%1" : "=r" (tmp) : "r" (src));
		return tmp;
 */
#else
		return sph_bswap64(*(const sph_u64 *)src);
#endif
#else
		return *(const sph_u64 *)src;
#endif
	} else {
		return (sph_u64)(((const unsigned char *)src)[0])
			| ((sph_u64)(((const unsigned char *)src)[1]) << 8)
			| ((sph_u64)(((const unsigned char *)src)[2]) << 16)
			| ((sph_u64)(((const unsigned char *)src)[3]) << 24)
			| ((sph_u64)(((const unsigned char *)src)[4]) << 32)
			| ((sph_u64)(((const unsigned char *)src)[5]) << 40)
			| ((sph_u64)(((const unsigned char *)src)[6]) << 48)
			| ((sph_u64)(((const unsigned char *)src)[7]) << 56);
	}
#endif
#else
	return (sph_u64)(((const unsigned char *)src)[0])
		| ((sph_u64)(((const unsigned char *)src)[1]) << 8)
		| ((sph_u64)(((const unsigned char *)src)[2]) << 16)
		| ((sph_u64)(((const unsigned char *)src)[3]) << 24)
		| ((sph_u64)(((const unsigned char *)src)[4]) << 32)
		| ((sph_u64)(((const unsigned char *)src)[5]) << 40)
		| ((sph_u64)(((const unsigned char *)src)[6]) << 48)
		| ((sph_u64)(((const unsigned char *)src)[7]) << 56);
#endif
}

/**
 * Decode a 64-bit value from the provided buffer (little endian convention).
 * The source buffer must be properly aligned.
 *
 * @param src   the source buffer (64-bit aligned)
 * @return  the decoded value
 */
static SPH_INLINE sph_u64
sph_dec64le_aligned(const void *src)
{
#if SPH_LITTLE_ENDIAN
	return *(const sph_u64 *)src;
#elif SPH_BIG_ENDIAN
#if SPH_SPARCV9_GCC_64 && !SPH_NO_ASM
	sph_u64 tmp;

	__asm__ __volatile__ ("ldxa [%1]0x88,%0" : "=r" (tmp) : "r" (src));
	return tmp;
/*
 * Not worth it generally.
 *
#elif SPH_PPC32_GCC && !SPH_NO_ASM
	return (sph_u64)sph_dec32le_aligned(src)
		| ((sph_u64)sph_dec32le_aligned((const char *)src + 4) << 32);
#elif SPH_PPC64_GCC && !SPH_NO_ASM
	sph_u64 tmp;

	__asm__ __volatile__ ("ldbrx %0,0,%1" : "=r" (tmp) : "r" (src));
	return tmp;
 */
#else
	return sph_bswap64(*(const sph_u64 *)src);
#endif
#else
	return (sph_u64)(((const unsigned char *)src)[0])
		| ((sph_u64)(((const unsigned char *)src)[1]) << 8)
		| ((sph_u64)(((const unsigned char *)src)[2]) << 16)
		| ((sph_u64)(((const unsigned char *)src)[3]) << 24)
		| ((sph_u64)(((const unsigned char *)src)[4]) << 32)
		| ((sph_u64)(((const unsigned char *)src)[5]) << 40)
		| ((sph_u64)(((const unsigned char *)src)[6]) << 48)
		| ((sph_u64)(((const unsigned char *)src)[7]) << 56);
#endif
}

#endif

#define AESx(x)   SPH_C32(x)
#define AES0      AES0_LE
#define AES1      AES1_LE
#define AES2      AES2_LE
#define AES3      AES3_LE

#define AES_ROUND_LE(X0, X1, X2, X3, K0, K1, K2, K3, Y0, Y1, Y2, Y3)   do { \
        (Y0) = AES0[(X0) & 0xFF] \
            ^ AES1[((X1) >> 8) & 0xFF] \
            ^ AES2[((X2) >> 16) & 0xFF] \
            ^ AES3[((X3) >> 24) & 0xFF] ^ (K0); \
        (Y1) = AES0[(X1) & 0xFF] \
            ^ AES1[((X2) >> 8) & 0xFF] \
            ^ AES2[((X3) >> 16) & 0xFF] \
            ^ AES3[((X0) >> 24) & 0xFF] ^ (K1); \
        (Y2) = AES0[(X2) & 0xFF] \
            ^ AES1[((X3) >> 8) & 0xFF] \
            ^ AES2[((X0) >> 16) & 0xFF] \
            ^ AES3[((X1) >> 24) & 0xFF] ^ (K2); \
        (Y3) = AES0[(X3) & 0xFF] \
            ^ AES1[((X0) >> 8) & 0xFF] \
            ^ AES2[((X1) >> 16) & 0xFF] \
            ^ AES3[((X2) >> 24) & 0xFF] ^ (K3); \
    } while (0)

#define AES_ROUND_NOKEY_LE(X0, X1, X2, X3, Y0, Y1, Y2, Y3) \
    AES_ROUND_LE(X0, X1, X2, X3, 0, 0, 0, 0, Y0, Y1, Y2, Y3)

/*
 * The AES*[] tables allow us to perform a fast evaluation of an AES
 * round; table AESi[] combines SubBytes for a byte at row i, and
 * MixColumns for the column where that byte goes after ShiftRows.
 */

static const sph_u32 AES0[256] = {
    AESx(0xA56363C6), AESx(0x847C7CF8), AESx(0x997777EE), AESx(0x8D7B7BF6),
    AESx(0x0DF2F2FF), AESx(0xBD6B6BD6), AESx(0xB16F6FDE), AESx(0x54C5C591),
    AESx(0x50303060), AESx(0x03010102), AESx(0xA96767CE), AESx(0x7D2B2B56),
    AESx(0x19FEFEE7), AESx(0x62D7D7B5), AESx(0xE6ABAB4D), AESx(0x9A7676EC),
    AESx(0x45CACA8F), AESx(0x9D82821F), AESx(0x40C9C989), AESx(0x877D7DFA),
    AESx(0x15FAFAEF), AESx(0xEB5959B2), AESx(0xC947478E), AESx(0x0BF0F0FB),
    AESx(0xECADAD41), AESx(0x67D4D4B3), AESx(0xFDA2A25F), AESx(0xEAAFAF45),
    AESx(0xBF9C9C23), AESx(0xF7A4A453), AESx(0x967272E4), AESx(0x5BC0C09B),
    AESx(0xC2B7B775), AESx(0x1CFDFDE1), AESx(0xAE93933D), AESx(0x6A26264C),
    AESx(0x5A36366C), AESx(0x413F3F7E), AESx(0x02F7F7F5), AESx(0x4FCCCC83),
    AESx(0x5C343468), AESx(0xF4A5A551), AESx(0x34E5E5D1), AESx(0x08F1F1F9),
    AESx(0x937171E2), AESx(0x73D8D8AB), AESx(0x53313162), AESx(0x3F15152A),
    AESx(0x0C040408), AESx(0x52C7C795), AESx(0x65232346), AESx(0x5EC3C39D),
    AESx(0x28181830), AESx(0xA1969637), AESx(0x0F05050A), AESx(0xB59A9A2F),
    AESx(0x0907070E), AESx(0x36121224), AESx(0x9B80801B), AESx(0x3DE2E2DF),
    AESx(0x26EBEBCD), AESx(0x6927274E), AESx(0xCDB2B27F), AESx(0x9F7575EA),
    AESx(0x1B090912), AESx(0x9E83831D), AESx(0x742C2C58), AESx(0x2E1A1A34),
    AESx(0x2D1B1B36), AESx(0xB26E6EDC), AESx(0xEE5A5AB4), AESx(0xFBA0A05B),
    AESx(0xF65252A4), AESx(0x4D3B3B76), AESx(0x61D6D6B7), AESx(0xCEB3B37D),
    AESx(0x7B292952), AESx(0x3EE3E3DD), AESx(0x712F2F5E), AESx(0x97848413),
    AESx(0xF55353A6), AESx(0x68D1D1B9), AESx(0x00000000), AESx(0x2CEDEDC1),
    AESx(0x60202040), AESx(0x1FFCFCE3), AESx(0xC8B1B179), AESx(0xED5B5BB6),
    AESx(0xBE6A6AD4), AESx(0x46CBCB8D), AESx(0xD9BEBE67), AESx(0x4B393972),
    AESx(0xDE4A4A94), AESx(0xD44C4C98), AESx(0xE85858B0), AESx(0x4ACFCF85),
    AESx(0x6BD0D0BB), AESx(0x2AEFEFC5), AESx(0xE5AAAA4F), AESx(0x16FBFBED),
    AESx(0xC5434386), AESx(0xD74D4D9A), AESx(0x55333366), AESx(0x94858511),
    AESx(0xCF45458A), AESx(0x10F9F9E9), AESx(0x06020204), AESx(0x817F7FFE),
    AESx(0xF05050A0), AESx(0x443C3C78), AESx(0xBA9F9F25), AESx(0xE3A8A84B),
    AESx(0xF35151A2), AESx(0xFEA3A35D), AESx(0xC0404080), AESx(0x8A8F8F05),
    AESx(0xAD92923F), AESx(0xBC9D9D21), AESx(0x48383870), AESx(0x04F5F5F1),
    AESx(0xDFBCBC63), AESx(0xC1B6B677), AESx(0x75DADAAF), AESx(0x63212142),
    AESx(0x30101020), AESx(0x1AFFFFE5), AESx(0x0EF3F3FD), AESx(0x6DD2D2BF),
    AESx(0x4CCDCD81), AESx(0x140C0C18), AESx(0x35131326), AESx(0x2FECECC3),
    AESx(0xE15F5FBE), AESx(0xA2979735), AESx(0xCC444488), AESx(0x3917172E),
    AESx(0x57C4C493), AESx(0xF2A7A755), AESx(0x827E7EFC), AESx(0x473D3D7A),
    AESx(0xAC6464C8), AESx(0xE75D5DBA), AESx(0x2B191932), AESx(0x957373E6),
    AESx(0xA06060C0), AESx(0x98818119), AESx(0xD14F4F9E), AESx(0x7FDCDCA3),
    AESx(0x66222244), AESx(0x7E2A2A54), AESx(0xAB90903B), AESx(0x8388880B),
    AESx(0xCA46468C), AESx(0x29EEEEC7), AESx(0xD3B8B86B), AESx(0x3C141428),
    AESx(0x79DEDEA7), AESx(0xE25E5EBC), AESx(0x1D0B0B16), AESx(0x76DBDBAD),
    AESx(0x3BE0E0DB), AESx(0x56323264), AESx(0x4E3A3A74), AESx(0x1E0A0A14),
    AESx(0xDB494992), AESx(0x0A06060C), AESx(0x6C242448), AESx(0xE45C5CB8),
    AESx(0x5DC2C29F), AESx(0x6ED3D3BD), AESx(0xEFACAC43), AESx(0xA66262C4),
    AESx(0xA8919139), AESx(0xA4959531), AESx(0x37E4E4D3), AESx(0x8B7979F2),
    AESx(0x32E7E7D5), AESx(0x43C8C88B), AESx(0x5937376E), AESx(0xB76D6DDA),
    AESx(0x8C8D8D01), AESx(0x64D5D5B1), AESx(0xD24E4E9C), AESx(0xE0A9A949),
    AESx(0xB46C6CD8), AESx(0xFA5656AC), AESx(0x07F4F4F3), AESx(0x25EAEACF),
    AESx(0xAF6565CA), AESx(0x8E7A7AF4), AESx(0xE9AEAE47), AESx(0x18080810),
    AESx(0xD5BABA6F), AESx(0x887878F0), AESx(0x6F25254A), AESx(0x722E2E5C),
    AESx(0x241C1C38), AESx(0xF1A6A657), AESx(0xC7B4B473), AESx(0x51C6C697),
    AESx(0x23E8E8CB), AESx(0x7CDDDDA1), AESx(0x9C7474E8), AESx(0x211F1F3E),
    AESx(0xDD4B4B96), AESx(0xDCBDBD61), AESx(0x868B8B0D), AESx(0x858A8A0F),
    AESx(0x907070E0), AESx(0x423E3E7C), AESx(0xC4B5B571), AESx(0xAA6666CC),
    AESx(0xD8484890), AESx(0x05030306), AESx(0x01F6F6F7), AESx(0x120E0E1C),
    AESx(0xA36161C2), AESx(0x5F35356A), AESx(0xF95757AE), AESx(0xD0B9B969),
    AESx(0x91868617), AESx(0x58C1C199), AESx(0x271D1D3A), AESx(0xB99E9E27),
    AESx(0x38E1E1D9), AESx(0x13F8F8EB), AESx(0xB398982B), AESx(0x33111122),
    AESx(0xBB6969D2), AESx(0x70D9D9A9), AESx(0x898E8E07), AESx(0xA7949433),
    AESx(0xB69B9B2D), AESx(0x221E1E3C), AESx(0x92878715), AESx(0x20E9E9C9),
    AESx(0x49CECE87), AESx(0xFF5555AA), AESx(0x78282850), AESx(0x7ADFDFA5),
    AESx(0x8F8C8C03), AESx(0xF8A1A159), AESx(0x80898909), AESx(0x170D0D1A),
    AESx(0xDABFBF65), AESx(0x31E6E6D7), AESx(0xC6424284), AESx(0xB86868D0),
    AESx(0xC3414182), AESx(0xB0999929), AESx(0x772D2D5A), AESx(0x110F0F1E),
    AESx(0xCBB0B07B), AESx(0xFC5454A8), AESx(0xD6BBBB6D), AESx(0x3A16162C)
};

static const sph_u32 AES1[256] = {
    AESx(0x6363C6A5), AESx(0x7C7CF884), AESx(0x7777EE99), AESx(0x7B7BF68D),
    AESx(0xF2F2FF0D), AESx(0x6B6BD6BD), AESx(0x6F6FDEB1), AESx(0xC5C59154),
    AESx(0x30306050), AESx(0x01010203), AESx(0x6767CEA9), AESx(0x2B2B567D),
    AESx(0xFEFEE719), AESx(0xD7D7B562), AESx(0xABAB4DE6), AESx(0x7676EC9A),
    AESx(0xCACA8F45), AESx(0x82821F9D), AESx(0xC9C98940), AESx(0x7D7DFA87),
    AESx(0xFAFAEF15), AESx(0x5959B2EB), AESx(0x47478EC9), AESx(0xF0F0FB0B),
    AESx(0xADAD41EC), AESx(0xD4D4B367), AESx(0xA2A25FFD), AESx(0xAFAF45EA),
    AESx(0x9C9C23BF), AESx(0xA4A453F7), AESx(0x7272E496), AESx(0xC0C09B5B),
    AESx(0xB7B775C2), AESx(0xFDFDE11C), AESx(0x93933DAE), AESx(0x26264C6A),
    AESx(0x36366C5A), AESx(0x3F3F7E41), AESx(0xF7F7F502), AESx(0xCCCC834F),
    AESx(0x3434685C), AESx(0xA5A551F4), AESx(0xE5E5D134), AESx(0xF1F1F908),
    AESx(0x7171E293), AESx(0xD8D8AB73), AESx(0x31316253), AESx(0x15152A3F),
    AESx(0x0404080C), AESx(0xC7C79552), AESx(0x23234665), AESx(0xC3C39D5E),
    AESx(0x18183028), AESx(0x969637A1), AESx(0x05050A0F), AESx(0x9A9A2FB5),
    AESx(0x07070E09), AESx(0x12122436), AESx(0x80801B9B), AESx(0xE2E2DF3D),
    AESx(0xEBEBCD26), AESx(0x27274E69), AESx(0xB2B27FCD), AESx(0x7575EA9F),
    AESx(0x0909121B), AESx(0x83831D9E), AESx(0x2C2C5874), AESx(0x1A1A342E),
    AESx(0x1B1B362D), AESx(0x6E6EDCB2), AESx(0x5A5AB4EE), AESx(0xA0A05BFB),
    AESx(0x5252A4F6), AESx(0x3B3B764D), AESx(0xD6D6B761), AESx(0xB3B37DCE),
    AESx(0x2929527B), AESx(0xE3E3DD3E), AESx(0x2F2F5E71), AESx(0x84841397),
    AESx(0x5353A6F5), AESx(0xD1D1B968), AESx(0x00000000), AESx(0xEDEDC12C),
    AESx(0x20204060), AESx(0xFCFCE31F), AESx(0xB1B179C8), AESx(0x5B5BB6ED),
    AESx(0x6A6AD4BE), AESx(0xCBCB8D46), AESx(0xBEBE67D9), AESx(0x3939724B),
    AESx(0x4A4A94DE), AESx(0x4C4C98D4), AESx(0x5858B0E8), AESx(0xCFCF854A),
    AESx(0xD0D0BB6B), AESx(0xEFEFC52A), AESx(0xAAAA4FE5), AESx(0xFBFBED16),
    AESx(0x434386C5), AESx(0x4D4D9AD7), AESx(0x33336655), AESx(0x85851194),
    AESx(0x45458ACF), AESx(0xF9F9E910), AESx(0x02020406), AESx(0x7F7FFE81),
    AESx(0x5050A0F0), AESx(0x3C3C7844), AESx(0x9F9F25BA), AESx(0xA8A84BE3),
    AESx(0x5151A2F3), AESx(0xA3A35DFE), AESx(0x404080C0), AESx(0x8F8F058A),
    AESx(0x92923FAD), AESx(0x9D9D21BC), AESx(0x38387048), AESx(0xF5F5F104),
    AESx(0xBCBC63DF), AESx(0xB6B677C1), AESx(0xDADAAF75), AESx(0x21214263),
    AESx(0x10102030), AESx(0xFFFFE51A), AESx(0xF3F3FD0E), AESx(0xD2D2BF6D),
    AESx(0xCDCD814C), AESx(0x0C0C1814), AESx(0x13132635), AESx(0xECECC32F),
    AESx(0x5F5FBEE1), AESx(0x979735A2), AESx(0x444488CC), AESx(0x17172E39),
    AESx(0xC4C49357), AESx(0xA7A755F2), AESx(0x7E7EFC82), AESx(0x3D3D7A47),
    AESx(0x6464C8AC), AESx(0x5D5DBAE7), AESx(0x1919322B), AESx(0x7373E695),
    AESx(0x6060C0A0), AESx(0x81811998), AESx(0x4F4F9ED1), AESx(0xDCDCA37F),
    AESx(0x22224466), AESx(0x2A2A547E), AESx(0x90903BAB), AESx(0x88880B83),
    AESx(0x46468CCA), AESx(0xEEEEC729), AESx(0xB8B86BD3), AESx(0x1414283C),
    AESx(0xDEDEA779), AESx(0x5E5EBCE2), AESx(0x0B0B161D), AESx(0xDBDBAD76),
    AESx(0xE0E0DB3B), AESx(0x32326456), AESx(0x3A3A744E), AESx(0x0A0A141E),
    AESx(0x494992DB), AESx(0x06060C0A), AESx(0x2424486C), AESx(0x5C5CB8E4),
    AESx(0xC2C29F5D), AESx(0xD3D3BD6E), AESx(0xACAC43EF), AESx(0x6262C4A6),
    AESx(0x919139A8), AESx(0x959531A4), AESx(0xE4E4D337), AESx(0x7979F28B),
    AESx(0xE7E7D532), AESx(0xC8C88B43), AESx(0x37376E59), AESx(0x6D6DDAB7),
    AESx(0x8D8D018C), AESx(0xD5D5B164), AESx(0x4E4E9CD2), AESx(0xA9A949E0),
    AESx(0x6C6CD8B4), AESx(0x5656ACFA), AESx(0xF4F4F307), AESx(0xEAEACF25),
    AESx(0x6565CAAF), AESx(0x7A7AF48E), AESx(0xAEAE47E9), AESx(0x08081018),
    AESx(0xBABA6FD5), AESx(0x7878F088), AESx(0x25254A6F), AESx(0x2E2E5C72),
    AESx(0x1C1C3824), AESx(0xA6A657F1), AESx(0xB4B473C7), AESx(0xC6C69751),
    AESx(0xE8E8CB23), AESx(0xDDDDA17C), AESx(0x7474E89C), AESx(0x1F1F3E21),
    AESx(0x4B4B96DD), AESx(0xBDBD61DC), AESx(0x8B8B0D86), AESx(0x8A8A0F85),
    AESx(0x7070E090), AESx(0x3E3E7C42), AESx(0xB5B571C4), AESx(0x6666CCAA),
    AESx(0x484890D8), AESx(0x03030605), AESx(0xF6F6F701), AESx(0x0E0E1C12),
    AESx(0x6161C2A3), AESx(0x35356A5F), AESx(0x5757AEF9), AESx(0xB9B969D0),
    AESx(0x86861791), AESx(0xC1C19958), AESx(0x1D1D3A27), AESx(0x9E9E27B9),
    AESx(0xE1E1D938), AESx(0xF8F8EB13), AESx(0x98982BB3), AESx(0x11112233),
    AESx(0x6969D2BB), AESx(0xD9D9A970), AESx(0x8E8E0789), AESx(0x949433A7),
    AESx(0x9B9B2DB6), AESx(0x1E1E3C22), AESx(0x87871592), AESx(0xE9E9C920),
    AESx(0xCECE8749), AESx(0x5555AAFF), AESx(0x28285078), AESx(0xDFDFA57A),
    AESx(0x8C8C038F), AESx(0xA1A159F8), AESx(0x89890980), AESx(0x0D0D1A17),
    AESx(0xBFBF65DA), AESx(0xE6E6D731), AESx(0x424284C6), AESx(0x6868D0B8),
    AESx(0x414182C3), AESx(0x999929B0), AESx(0x2D2D5A77), AESx(0x0F0F1E11),
    AESx(0xB0B07BCB), AESx(0x5454A8FC), AESx(0xBBBB6DD6), AESx(0x16162C3A)
};

static const sph_u32 AES2[256] = {
    AESx(0x63C6A563), AESx(0x7CF8847C), AESx(0x77EE9977), AESx(0x7BF68D7B),
    AESx(0xF2FF0DF2), AESx(0x6BD6BD6B), AESx(0x6FDEB16F), AESx(0xC59154C5),
    AESx(0x30605030), AESx(0x01020301), AESx(0x67CEA967), AESx(0x2B567D2B),
    AESx(0xFEE719FE), AESx(0xD7B562D7), AESx(0xAB4DE6AB), AESx(0x76EC9A76),
    AESx(0xCA8F45CA), AESx(0x821F9D82), AESx(0xC98940C9), AESx(0x7DFA877D),
    AESx(0xFAEF15FA), AESx(0x59B2EB59), AESx(0x478EC947), AESx(0xF0FB0BF0),
    AESx(0xAD41ECAD), AESx(0xD4B367D4), AESx(0xA25FFDA2), AESx(0xAF45EAAF),
    AESx(0x9C23BF9C), AESx(0xA453F7A4), AESx(0x72E49672), AESx(0xC09B5BC0),
    AESx(0xB775C2B7), AESx(0xFDE11CFD), AESx(0x933DAE93), AESx(0x264C6A26),
    AESx(0x366C5A36), AESx(0x3F7E413F), AESx(0xF7F502F7), AESx(0xCC834FCC),
    AESx(0x34685C34), AESx(0xA551F4A5), AESx(0xE5D134E5), AESx(0xF1F908F1),
    AESx(0x71E29371), AESx(0xD8AB73D8), AESx(0x31625331), AESx(0x152A3F15),
    AESx(0x04080C04), AESx(0xC79552C7), AESx(0x23466523), AESx(0xC39D5EC3),
    AESx(0x18302818), AESx(0x9637A196), AESx(0x050A0F05), AESx(0x9A2FB59A),
    AESx(0x070E0907), AESx(0x12243612), AESx(0x801B9B80), AESx(0xE2DF3DE2),
    AESx(0xEBCD26EB), AESx(0x274E6927), AESx(0xB27FCDB2), AESx(0x75EA9F75),
    AESx(0x09121B09), AESx(0x831D9E83), AESx(0x2C58742C), AESx(0x1A342E1A),
    AESx(0x1B362D1B), AESx(0x6EDCB26E), AESx(0x5AB4EE5A), AESx(0xA05BFBA0),
    AESx(0x52A4F652), AESx(0x3B764D3B), AESx(0xD6B761D6), AESx(0xB37DCEB3),
    AESx(0x29527B29), AESx(0xE3DD3EE3), AESx(0x2F5E712F), AESx(0x84139784),
    AESx(0x53A6F553), AESx(0xD1B968D1), AESx(0x00000000), AESx(0xEDC12CED),
    AESx(0x20406020), AESx(0xFCE31FFC), AESx(0xB179C8B1), AESx(0x5BB6ED5B),
    AESx(0x6AD4BE6A), AESx(0xCB8D46CB), AESx(0xBE67D9BE), AESx(0x39724B39),
    AESx(0x4A94DE4A), AESx(0x4C98D44C), AESx(0x58B0E858), AESx(0xCF854ACF),
    AESx(0xD0BB6BD0), AESx(0xEFC52AEF), AESx(0xAA4FE5AA), AESx(0xFBED16FB),
    AESx(0x4386C543), AESx(0x4D9AD74D), AESx(0x33665533), AESx(0x85119485),
    AESx(0x458ACF45), AESx(0xF9E910F9), AESx(0x02040602), AESx(0x7FFE817F),
    AESx(0x50A0F050), AESx(0x3C78443C), AESx(0x9F25BA9F), AESx(0xA84BE3A8),
    AESx(0x51A2F351), AESx(0xA35DFEA3), AESx(0x4080C040), AESx(0x8F058A8F),
    AESx(0x923FAD92), AESx(0x9D21BC9D), AESx(0x38704838), AESx(0xF5F104F5),
    AESx(0xBC63DFBC), AESx(0xB677C1B6), AESx(0xDAAF75DA), AESx(0x21426321),
    AESx(0x10203010), AESx(0xFFE51AFF), AESx(0xF3FD0EF3), AESx(0xD2BF6DD2),
    AESx(0xCD814CCD), AESx(0x0C18140C), AESx(0x13263513), AESx(0xECC32FEC),
    AESx(0x5FBEE15F), AESx(0x9735A297), AESx(0x4488CC44), AESx(0x172E3917),
    AESx(0xC49357C4), AESx(0xA755F2A7), AESx(0x7EFC827E), AESx(0x3D7A473D),
    AESx(0x64C8AC64), AESx(0x5DBAE75D), AESx(0x19322B19), AESx(0x73E69573),
    AESx(0x60C0A060), AESx(0x81199881), AESx(0x4F9ED14F), AESx(0xDCA37FDC),
    AESx(0x22446622), AESx(0x2A547E2A), AESx(0x903BAB90), AESx(0x880B8388),
    AESx(0x468CCA46), AESx(0xEEC729EE), AESx(0xB86BD3B8), AESx(0x14283C14),
    AESx(0xDEA779DE), AESx(0x5EBCE25E), AESx(0x0B161D0B), AESx(0xDBAD76DB),
    AESx(0xE0DB3BE0), AESx(0x32645632), AESx(0x3A744E3A), AESx(0x0A141E0A),
    AESx(0x4992DB49), AESx(0x060C0A06), AESx(0x24486C24), AESx(0x5CB8E45C),
    AESx(0xC29F5DC2), AESx(0xD3BD6ED3), AESx(0xAC43EFAC), AESx(0x62C4A662),
    AESx(0x9139A891), AESx(0x9531A495), AESx(0xE4D337E4), AESx(0x79F28B79),
    AESx(0xE7D532E7), AESx(0xC88B43C8), AESx(0x376E5937), AESx(0x6DDAB76D),
    AESx(0x8D018C8D), AESx(0xD5B164D5), AESx(0x4E9CD24E), AESx(0xA949E0A9),
    AESx(0x6CD8B46C), AESx(0x56ACFA56), AESx(0xF4F307F4), AESx(0xEACF25EA),
    AESx(0x65CAAF65), AESx(0x7AF48E7A), AESx(0xAE47E9AE), AESx(0x08101808),
    AESx(0xBA6FD5BA), AESx(0x78F08878), AESx(0x254A6F25), AESx(0x2E5C722E),
    AESx(0x1C38241C), AESx(0xA657F1A6), AESx(0xB473C7B4), AESx(0xC69751C6),
    AESx(0xE8CB23E8), AESx(0xDDA17CDD), AESx(0x74E89C74), AESx(0x1F3E211F),
    AESx(0x4B96DD4B), AESx(0xBD61DCBD), AESx(0x8B0D868B), AESx(0x8A0F858A),
    AESx(0x70E09070), AESx(0x3E7C423E), AESx(0xB571C4B5), AESx(0x66CCAA66),
    AESx(0x4890D848), AESx(0x03060503), AESx(0xF6F701F6), AESx(0x0E1C120E),
    AESx(0x61C2A361), AESx(0x356A5F35), AESx(0x57AEF957), AESx(0xB969D0B9),
    AESx(0x86179186), AESx(0xC19958C1), AESx(0x1D3A271D), AESx(0x9E27B99E),
    AESx(0xE1D938E1), AESx(0xF8EB13F8), AESx(0x982BB398), AESx(0x11223311),
    AESx(0x69D2BB69), AESx(0xD9A970D9), AESx(0x8E07898E), AESx(0x9433A794),
    AESx(0x9B2DB69B), AESx(0x1E3C221E), AESx(0x87159287), AESx(0xE9C920E9),
    AESx(0xCE8749CE), AESx(0x55AAFF55), AESx(0x28507828), AESx(0xDFA57ADF),
    AESx(0x8C038F8C), AESx(0xA159F8A1), AESx(0x89098089), AESx(0x0D1A170D),
    AESx(0xBF65DABF), AESx(0xE6D731E6), AESx(0x4284C642), AESx(0x68D0B868),
    AESx(0x4182C341), AESx(0x9929B099), AESx(0x2D5A772D), AESx(0x0F1E110F),
    AESx(0xB07BCBB0), AESx(0x54A8FC54), AESx(0xBB6DD6BB), AESx(0x162C3A16)
};

static const sph_u32 AES3[256] = {
    AESx(0xC6A56363), AESx(0xF8847C7C), AESx(0xEE997777), AESx(0xF68D7B7B),
    AESx(0xFF0DF2F2), AESx(0xD6BD6B6B), AESx(0xDEB16F6F), AESx(0x9154C5C5),
    AESx(0x60503030), AESx(0x02030101), AESx(0xCEA96767), AESx(0x567D2B2B),
    AESx(0xE719FEFE), AESx(0xB562D7D7), AESx(0x4DE6ABAB), AESx(0xEC9A7676),
    AESx(0x8F45CACA), AESx(0x1F9D8282), AESx(0x8940C9C9), AESx(0xFA877D7D),
    AESx(0xEF15FAFA), AESx(0xB2EB5959), AESx(0x8EC94747), AESx(0xFB0BF0F0),
    AESx(0x41ECADAD), AESx(0xB367D4D4), AESx(0x5FFDA2A2), AESx(0x45EAAFAF),
    AESx(0x23BF9C9C), AESx(0x53F7A4A4), AESx(0xE4967272), AESx(0x9B5BC0C0),
    AESx(0x75C2B7B7), AESx(0xE11CFDFD), AESx(0x3DAE9393), AESx(0x4C6A2626),
    AESx(0x6C5A3636), AESx(0x7E413F3F), AESx(0xF502F7F7), AESx(0x834FCCCC),
    AESx(0x685C3434), AESx(0x51F4A5A5), AESx(0xD134E5E5), AESx(0xF908F1F1),
    AESx(0xE2937171), AESx(0xAB73D8D8), AESx(0x62533131), AESx(0x2A3F1515),
    AESx(0x080C0404), AESx(0x9552C7C7), AESx(0x46652323), AESx(0x9D5EC3C3),
    AESx(0x30281818), AESx(0x37A19696), AESx(0x0A0F0505), AESx(0x2FB59A9A),
    AESx(0x0E090707), AESx(0x24361212), AESx(0x1B9B8080), AESx(0xDF3DE2E2),
    AESx(0xCD26EBEB), AESx(0x4E692727), AESx(0x7FCDB2B2), AESx(0xEA9F7575),
    AESx(0x121B0909), AESx(0x1D9E8383), AESx(0x58742C2C), AESx(0x342E1A1A),
    AESx(0x362D1B1B), AESx(0xDCB26E6E), AESx(0xB4EE5A5A), AESx(0x5BFBA0A0),
    AESx(0xA4F65252), AESx(0x764D3B3B), AESx(0xB761D6D6), AESx(0x7DCEB3B3),
    AESx(0x527B2929), AESx(0xDD3EE3E3), AESx(0x5E712F2F), AESx(0x13978484),
    AESx(0xA6F55353), AESx(0xB968D1D1), AESx(0x00000000), AESx(0xC12CEDED),
    AESx(0x40602020), AESx(0xE31FFCFC), AESx(0x79C8B1B1), AESx(0xB6ED5B5B),
    AESx(0xD4BE6A6A), AESx(0x8D46CBCB), AESx(0x67D9BEBE), AESx(0x724B3939),
    AESx(0x94DE4A4A), AESx(0x98D44C4C), AESx(0xB0E85858), AESx(0x854ACFCF),
    AESx(0xBB6BD0D0), AESx(0xC52AEFEF), AESx(0x4FE5AAAA), AESx(0xED16FBFB),
    AESx(0x86C54343), AESx(0x9AD74D4D), AESx(0x66553333), AESx(0x11948585),
    AESx(0x8ACF4545), AESx(0xE910F9F9), AESx(0x04060202), AESx(0xFE817F7F),
    AESx(0xA0F05050), AESx(0x78443C3C), AESx(0x25BA9F9F), AESx(0x4BE3A8A8),
    AESx(0xA2F35151), AESx(0x5DFEA3A3), AESx(0x80C04040), AESx(0x058A8F8F),
    AESx(0x3FAD9292), AESx(0x21BC9D9D), AESx(0x70483838), AESx(0xF104F5F5),
    AESx(0x63DFBCBC), AESx(0x77C1B6B6), AESx(0xAF75DADA), AESx(0x42632121),
    AESx(0x20301010), AESx(0xE51AFFFF), AESx(0xFD0EF3F3), AESx(0xBF6DD2D2),
    AESx(0x814CCDCD), AESx(0x18140C0C), AESx(0x26351313), AESx(0xC32FECEC),
    AESx(0xBEE15F5F), AESx(0x35A29797), AESx(0x88CC4444), AESx(0x2E391717),
    AESx(0x9357C4C4), AESx(0x55F2A7A7), AESx(0xFC827E7E), AESx(0x7A473D3D),
    AESx(0xC8AC6464), AESx(0xBAE75D5D), AESx(0x322B1919), AESx(0xE6957373),
    AESx(0xC0A06060), AESx(0x19988181), AESx(0x9ED14F4F), AESx(0xA37FDCDC),
    AESx(0x44662222), AESx(0x547E2A2A), AESx(0x3BAB9090), AESx(0x0B838888),
    AESx(0x8CCA4646), AESx(0xC729EEEE), AESx(0x6BD3B8B8), AESx(0x283C1414),
    AESx(0xA779DEDE), AESx(0xBCE25E5E), AESx(0x161D0B0B), AESx(0xAD76DBDB),
    AESx(0xDB3BE0E0), AESx(0x64563232), AESx(0x744E3A3A), AESx(0x141E0A0A),
    AESx(0x92DB4949), AESx(0x0C0A0606), AESx(0x486C2424), AESx(0xB8E45C5C),
    AESx(0x9F5DC2C2), AESx(0xBD6ED3D3), AESx(0x43EFACAC), AESx(0xC4A66262),
    AESx(0x39A89191), AESx(0x31A49595), AESx(0xD337E4E4), AESx(0xF28B7979),
    AESx(0xD532E7E7), AESx(0x8B43C8C8), AESx(0x6E593737), AESx(0xDAB76D6D),
    AESx(0x018C8D8D), AESx(0xB164D5D5), AESx(0x9CD24E4E), AESx(0x49E0A9A9),
    AESx(0xD8B46C6C), AESx(0xACFA5656), AESx(0xF307F4F4), AESx(0xCF25EAEA),
    AESx(0xCAAF6565), AESx(0xF48E7A7A), AESx(0x47E9AEAE), AESx(0x10180808),
    AESx(0x6FD5BABA), AESx(0xF0887878), AESx(0x4A6F2525), AESx(0x5C722E2E),
    AESx(0x38241C1C), AESx(0x57F1A6A6), AESx(0x73C7B4B4), AESx(0x9751C6C6),
    AESx(0xCB23E8E8), AESx(0xA17CDDDD), AESx(0xE89C7474), AESx(0x3E211F1F),
    AESx(0x96DD4B4B), AESx(0x61DCBDBD), AESx(0x0D868B8B), AESx(0x0F858A8A),
    AESx(0xE0907070), AESx(0x7C423E3E), AESx(0x71C4B5B5), AESx(0xCCAA6666),
    AESx(0x90D84848), AESx(0x06050303), AESx(0xF701F6F6), AESx(0x1C120E0E),
    AESx(0xC2A36161), AESx(0x6A5F3535), AESx(0xAEF95757), AESx(0x69D0B9B9),
    AESx(0x17918686), AESx(0x9958C1C1), AESx(0x3A271D1D), AESx(0x27B99E9E),
    AESx(0xD938E1E1), AESx(0xEB13F8F8), AESx(0x2BB39898), AESx(0x22331111),
    AESx(0xD2BB6969), AESx(0xA970D9D9), AESx(0x07898E8E), AESx(0x33A79494),
    AESx(0x2DB69B9B), AESx(0x3C221E1E), AESx(0x15928787), AESx(0xC920E9E9),
    AESx(0x8749CECE), AESx(0xAAFF5555), AESx(0x50782828), AESx(0xA57ADFDF),
    AESx(0x038F8C8C), AESx(0x59F8A1A1), AESx(0x09808989), AESx(0x1A170D0D),
    AESx(0x65DABFBF), AESx(0xD731E6E6), AESx(0x84C64242), AESx(0xD0B86868),
    AESx(0x82C34141), AESx(0x29B09999), AESx(0x5A772D2D), AESx(0x1E110F0F),
    AESx(0x7BCBB0B0), AESx(0xA8FC5454), AESx(0x6DD6BBBB), AESx(0x2C3A1616)
};


#endif /* Doxygen excluded block */

#endif
