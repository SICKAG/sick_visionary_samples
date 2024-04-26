/*
* Botan 2.19.4 Amalgamation
* (C) 1999-2020 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AMALGAMATION_H_
#define BOTAN_AMALGAMATION_H_

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <iosfwd>
#include <istream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

/*
* Build configuration for Botan 2.19.4
*
* Automatically generated from
* 'configure.py --quiet --cc=gcc --amalgamation --minimized-build --enable-modules=aes,cbc,hmac,md5,sha2_32,sha2_64,auto_rng,system_rng --build-targets=static'
*
* Target
*  - Compiler: /usr/bin/c++ -fstack-protector -m64 -pthread -std=c++11 -D_REENTRANT -O3
*  - Arch: x86_64
*  - OS: linux
*/

#define BOTAN_VERSION_MAJOR 2
#define BOTAN_VERSION_MINOR 19
#define BOTAN_VERSION_PATCH 4
#define BOTAN_VERSION_DATESTAMP 0


#define BOTAN_VERSION_RELEASE_TYPE "unreleased"

#define BOTAN_VERSION_VC_REVISION "git:fb0a41bfa4e63b4f26302d90a2e2905e0ba2a400"

#define BOTAN_DISTRIBUTION_INFO "unspecified"

/* How many bits per limb in a BigInt */
#define BOTAN_MP_WORD_BITS 64


#define BOTAN_INSTALL_PREFIX R"(/usr/local)"
#define BOTAN_INSTALL_HEADER_DIR R"(include/botan-2)"
#define BOTAN_INSTALL_LIB_DIR R"(/usr/local/lib)"
#define BOTAN_LIB_LINK ""
#define BOTAN_LINK_FLAGS "-fstack-protector -m64 -pthread"

#define BOTAN_SYSTEM_CERT_BUNDLE "/etc/ssl/certs/ca-certificates.crt"

#ifndef BOTAN_DLL
  #define BOTAN_DLL 
#endif

/* Target identification and feature test macros */

#define BOTAN_TARGET_OS_IS_LINUX

#define BOTAN_TARGET_OS_HAS_ATOMICS
#define BOTAN_TARGET_OS_HAS_CLOCK_GETTIME
#define BOTAN_TARGET_OS_HAS_DEV_RANDOM
#define BOTAN_TARGET_OS_HAS_FILESYSTEM
#define BOTAN_TARGET_OS_HAS_GETAUXVAL
#define BOTAN_TARGET_OS_HAS_POSIX1
#define BOTAN_TARGET_OS_HAS_POSIX_MLOCK
#define BOTAN_TARGET_OS_HAS_PROC_FS
#define BOTAN_TARGET_OS_HAS_SOCKETS
#define BOTAN_TARGET_OS_HAS_THREAD_LOCAL
#define BOTAN_TARGET_OS_HAS_THREADS


#define BOTAN_BUILD_COMPILER_IS_GCC




#define BOTAN_TARGET_ARCH_IS_X86_64
#define BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN
#define BOTAN_TARGET_CPU_IS_X86_FAMILY
#define BOTAN_TARGET_CPU_HAS_NATIVE_64BIT

#define BOTAN_TARGET_SUPPORTS_AESNI
#define BOTAN_TARGET_SUPPORTS_AVX2
#define BOTAN_TARGET_SUPPORTS_BMI2
#define BOTAN_TARGET_SUPPORTS_RDRAND
#define BOTAN_TARGET_SUPPORTS_RDSEED
#define BOTAN_TARGET_SUPPORTS_SHA
#define BOTAN_TARGET_SUPPORTS_SSE2
#define BOTAN_TARGET_SUPPORTS_SSE41
#define BOTAN_TARGET_SUPPORTS_SSE42
#define BOTAN_TARGET_SUPPORTS_SSSE3






/*
* Module availability definitions
*/
#define BOTAN_HAS_AES 20131128
#define BOTAN_HAS_AUTO_RNG 20161126
#define BOTAN_HAS_AUTO_SEEDING_RNG 20160821
#define BOTAN_HAS_BLOCK_CIPHER 20131128
#define BOTAN_HAS_CIPHER_MODES 20180124
#define BOTAN_HAS_CIPHER_MODE_PADDING 20131128
#define BOTAN_HAS_CPUID 20170917
#define BOTAN_HAS_ENTROPY_SOURCE 20151120
#define BOTAN_HAS_HASH 20180112
#define BOTAN_HAS_HEX_CODEC 20131128
#define BOTAN_HAS_HMAC 20131128
#define BOTAN_HAS_HMAC_DRBG 20140319
#define BOTAN_HAS_MAC 20150626
#define BOTAN_HAS_MD5 20131128
#define BOTAN_HAS_MDX_HASH_FUNCTION 20131128
#define BOTAN_HAS_MODES 20150626
#define BOTAN_HAS_MODE_CBC 20131128
#define BOTAN_HAS_SHA2_32 20131128
#define BOTAN_HAS_SHA2_64 20131128
#define BOTAN_HAS_STATEFUL_RNG 20160819
#define BOTAN_HAS_SYSTEM_RNG 20141202
#define BOTAN_HAS_UTIL_FUNCTIONS 20180903


/*
* Local/misc configuration options (if any) follow
*/


/*
* Things you can edit (but probably shouldn't)
*/

#if !defined(BOTAN_DEPRECATED_PUBLIC_MEMBER_VARIABLES)

  #if defined(BOTAN_NO_DEPRECATED)
     #define BOTAN_DEPRECATED_PUBLIC_MEMBER_VARIABLES private
  #else
     #define BOTAN_DEPRECATED_PUBLIC_MEMBER_VARIABLES public
  #endif

#endif

/* How much to allocate for a buffer of no particular size */
#define BOTAN_DEFAULT_BUFFER_SIZE 1024

/*
* Total maximum amount of RAM (in KiB) we will lock into memory, even
* if the OS would let us lock more
*/
#define BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB 512

/*
* If BOTAN_MEM_POOL_USE_MMU_PROTECTIONS is defined, the Memory_Pool
* class used for mlock'ed memory will use OS calls to set page
* permissions so as to prohibit access to pages on the free list, then
* enable read/write access when the page is set to be used. This will
* turn (some) use after free bugs into a crash.
*
* The additional syscalls have a substantial performance impact, which
* is why this option is not enabled by default.
*/
#if defined(BOTAN_HAS_VALGRIND) || defined(BOTAN_ENABLE_DEBUG_ASSERTS)
   #define BOTAN_MEM_POOL_USE_MMU_PROTECTIONS
#endif

/*
* If enabled uses memset via volatile function pointer to zero memory,
* otherwise does a byte at a time write via a volatile pointer.
*/
#define BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO 1

/*
* Normally blinding is performed by choosing a random starting point (plus
* its inverse, of a form appropriate to the algorithm being blinded), and
* then choosing new blinding operands by successive squaring of both
* values. This is much faster than computing a new starting point but
* introduces some possible corelation
*
* To avoid possible leakage problems in long-running processes, the blinder
* periodically reinitializes the sequence. This value specifies how often
* a new sequence should be started.
*/
#define BOTAN_BLINDING_REINIT_INTERVAL 64

/*
* Userspace RNGs like HMAC_DRBG will reseed after a specified number
* of outputs are generated. Set to zero to disable automatic reseeding.
*/
#define BOTAN_RNG_DEFAULT_RESEED_INTERVAL 1024
#define BOTAN_RNG_RESEED_POLL_BITS 256

#define BOTAN_RNG_AUTO_RESEED_TIMEOUT std::chrono::milliseconds(10)
#define BOTAN_RNG_RESEED_DEFAULT_TIMEOUT std::chrono::milliseconds(50)

/*
* Specifies (in order) the list of entropy sources that will be used
* to seed an in-memory RNG.
*/
#define BOTAN_ENTROPY_DEFAULT_SOURCES \
   { "rdseed", "hwrng", "p9_darn", "getentropy", "dev_random", \
     "system_rng", "proc_walk", "system_stats" }

/* Multiplier on a block cipher's native parallelism */
#define BOTAN_BLOCK_CIPHER_PAR_MULT 4

/*
* These control the RNG used by the system RNG interface
*/
#define BOTAN_SYSTEM_RNG_DEVICE "/dev/urandom"
#define BOTAN_SYSTEM_RNG_POLL_DEVICES { "/dev/urandom", "/dev/random" }

/*
* This directory will be monitored by ProcWalking_EntropySource and
* the contents provided as entropy inputs to the RNG. May also be
* usefully set to something like "/sys", depending on the system being
* deployed to. Set to an empty string to disable.
*/
#define BOTAN_ENTROPY_PROC_FS_PATH "/proc"

/*
* These paramaters control how many bytes to read from the system
* PRNG, and how long to block if applicable. The timeout only applies
* to reading /dev/urandom and company.
*/
#define BOTAN_SYSTEM_RNG_POLL_REQUEST 64
#define BOTAN_SYSTEM_RNG_POLL_TIMEOUT_MS 20

/*
* When a PBKDF is self-tuning parameters, it will attempt to take about this
* amount of time to self-benchmark.
*/
#define BOTAN_PBKDF_TUNING_TIME std::chrono::milliseconds(10)

/*
* If no way of dynamically determining the cache line size for the
* system exists, this value is used as the default. Used by the side
* channel countermeasures rather than for alignment purposes, so it is
* better to be on the smaller side if the exact value cannot be
* determined. Typically 32 or 64 bytes on modern CPUs.
*/
#if !defined(BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE)
  #define BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE 32
#endif

/**
* Controls how AutoSeeded_RNG is instantiated
*/
#if !defined(BOTAN_AUTO_RNG_HMAC)

  #if defined(BOTAN_HAS_SHA2_64)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-384)"
  #elif defined(BOTAN_HAS_SHA2_32)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-256)"
  #elif defined(BOTAN_HAS_SHA3)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-3(256))"
  #elif defined(BOTAN_HAS_SHA1)
    #define BOTAN_AUTO_RNG_HMAC "HMAC(SHA-1)"
  #endif
  /* Otherwise, no hash found: leave BOTAN_AUTO_RNG_HMAC undefined */

#endif

/* Check for a common build problem */

#if defined(BOTAN_TARGET_ARCH_IS_X86_64) && ((defined(_MSC_VER) && !defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__x86_64__)) || \
                                             (defined(__GNUG__) && !defined(__x86_64__)))
    #error "Trying to compile Botan configured as x86_64 with non-x86_64 compiler."
#endif

#if defined(BOTAN_TARGET_ARCH_IS_X86_32) && ((defined(_MSC_VER) && defined(_WIN64)) || \
                                             (defined(__clang__) && !defined(__i386__)) || \
                                             (defined(__GNUG__) && !defined(__i386__)))

    #error "Trying to compile Botan configured as x86_32 with non-x86_32 compiler."
#endif

/* Should we use GCC-style inline assembler? */
#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || \
   defined(BOTAN_BUILD_COMPILER_IS_CLANG) || \
   defined(BOTAN_BUILD_COMPILER_IS_XLC) || \
   defined(BOTAN_BUILD_COMPILER_IS_SUN_STUDIO)

  #define BOTAN_USE_GCC_INLINE_ASM
#endif

/**
* Used to annotate API exports which are public and supported.
* These APIs will not be broken/removed unless strictly required for
* functionality or security, and only in new major versions.
* @param maj The major version this public API was released in
* @param min The minor version this public API was released in
*/
#define BOTAN_PUBLIC_API(maj,min) BOTAN_DLL

/**
* Used to annotate API exports which are public, but are now deprecated
* and which will be removed in a future major release.
*/
#define BOTAN_DEPRECATED_API(msg) BOTAN_DLL BOTAN_DEPRECATED(msg)

/**
* Used to annotate API exports which are public and can be used by
* applications if needed, but which are intentionally not documented,
* and which may change incompatibly in a future major version.
*/
#define BOTAN_UNSTABLE_API BOTAN_DLL

/**
* Used to annotate API exports which are exported but only for the
* purposes of testing. They should not be used by applications and
* may be removed or changed without notice.
*/
#define BOTAN_TEST_API BOTAN_DLL

/*
* Define BOTAN_GCC_VERSION
*/
#if defined(__GNUC__) && !defined(__clang__)
  #define BOTAN_GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__)
#else
  #define BOTAN_GCC_VERSION 0
#endif

/*
* Define BOTAN_CLANG_VERSION
*/
#if defined(__clang__)
  #define BOTAN_CLANG_VERSION (__clang_major__ * 10 + __clang_minor__)
#else
  #define BOTAN_CLANG_VERSION 0
#endif

/*
* Define BOTAN_FUNC_ISA
*/
#if (defined(__GNUC__) && !defined(__clang__)) || (BOTAN_CLANG_VERSION > 38)
  #define BOTAN_FUNC_ISA(isa) __attribute__ ((target(isa)))
#else
  #define BOTAN_FUNC_ISA(isa)
#endif

/*
* Define BOTAN_WARN_UNUSED_RESULT
*/
#if defined(__GNUC__) || defined(__clang__)
  #define BOTAN_WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
  #define BOTAN_WARN_UNUSED_RESULT
#endif

/*
* Define BOTAN_MALLOC_FN
*/
#if defined(__ibmxl__)
  /* XLC pretends to be both Clang and GCC, but is neither */
  #define BOTAN_MALLOC_FN __attribute__ ((malloc))
#elif defined(__GNUC__)
  #define BOTAN_MALLOC_FN __attribute__ ((malloc, alloc_size(1,2)))
#elif defined(_MSC_VER)
  #define BOTAN_MALLOC_FN __declspec(restrict)
#else
  #define BOTAN_MALLOC_FN
#endif

/*
* Define BOTAN_DEPRECATED
*/
#if !defined(BOTAN_NO_DEPRECATED_WARNINGS) && !defined(BOTAN_IS_BEING_BUILT) && !defined(BOTAN_AMALGAMATION_H_)

  #if defined(__clang__)
    #define BOTAN_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
    #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("message \"this header is deprecated\"")
    #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("message \"this header will be made internal in the future\"")

  #elif defined(_MSC_VER)
    #define BOTAN_DEPRECATED(msg) __declspec(deprecated(msg))
    #define BOTAN_DEPRECATED_HEADER(hdr) __pragma(message("this header is deprecated"))
    #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) __pragma(message("this header will be made internal in the future"))

  #elif defined(__GNUC__)
    /* msg supported since GCC 4.5, earliest we support is 4.8 */
    #define BOTAN_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
    #define BOTAN_DEPRECATED_HEADER(hdr) _Pragma("GCC warning \"this header is deprecated\"")
    #define BOTAN_FUTURE_INTERNAL_HEADER(hdr) _Pragma("GCC warning \"this header will be made internal in the future\"")
  #endif

#endif

#if !defined(BOTAN_DEPRECATED)
  #define BOTAN_DEPRECATED(msg)
#endif

#if !defined(BOTAN_DEPRECATED_HEADER)
  #define BOTAN_DEPRECATED_HEADER(hdr)
#endif

#if !defined(BOTAN_FUTURE_INTERNAL_HEADER)
  #define BOTAN_FUTURE_INTERNAL_HEADER(hdr)
#endif

/*
* Define BOTAN_NORETURN
*/
#if !defined(BOTAN_NORETURN)

  #if defined (__clang__) || defined (__GNUC__)
    #define BOTAN_NORETURN __attribute__ ((__noreturn__))

  #elif defined (_MSC_VER)
    #define BOTAN_NORETURN __declspec(noreturn)

  #else
    #define BOTAN_NORETURN
  #endif

#endif

/*
* Define BOTAN_THREAD_LOCAL
*/
#if !defined(BOTAN_THREAD_LOCAL)

  #if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_TARGET_OS_HAS_THREAD_LOCAL)
    #define BOTAN_THREAD_LOCAL thread_local
  #else
    #define BOTAN_THREAD_LOCAL /**/
  #endif

#endif

/*
* Define BOTAN_IF_CONSTEXPR
*/
#if !defined(BOTAN_IF_CONSTEXPR)
   #if __cplusplus >= 201703
      #define BOTAN_IF_CONSTEXPR if constexpr
   #else
      #define BOTAN_IF_CONSTEXPR if
   #endif
#endif

/*
* Define BOTAN_PARALLEL_FOR
*/
#if !defined(BOTAN_PARALLEL_FOR)

#if defined(BOTAN_TARGET_HAS_OPENMP)
  #define BOTAN_PARALLEL_FOR _Pragma("omp parallel for") for
#else
  #define BOTAN_PARALLEL_FOR for
#endif

#endif

#if !defined(BOTAN_ALIGNAS)

#if defined(__GNUC__) && (__GNUC__ == 4) && (__GNUC_MINOR__ < 8)
  #define BOTAN_ALIGNAS(x) /**/
#else
  #define BOTAN_ALIGNAS(x) alignas(x)
#endif

#endif

/*
* Define BOTAN_FORCE_INLINE
*/
#if !defined(BOTAN_FORCE_INLINE)

  #if defined (__clang__) || defined (__GNUC__)
    #define BOTAN_FORCE_INLINE __attribute__ ((__always_inline__)) inline

  #elif defined (_MSC_VER)
    #define BOTAN_FORCE_INLINE __forceinline

  #else
    #define BOTAN_FORCE_INLINE inline
  #endif

#endif

/*
* Define BOTAN_PARALLEL_SIMD_FOR
*/
#if !defined(BOTAN_PARALLEL_SIMD_FOR)

#if defined(BOTAN_TARGET_HAS_OPENMP)
  #define BOTAN_PARALLEL_SIMD_FOR _Pragma("omp simd") for
#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) && (BOTAN_GCC_VERSION >= 490)
  #define BOTAN_PARALLEL_SIMD_FOR _Pragma("GCC ivdep") for
#else
  #define BOTAN_PARALLEL_SIMD_FOR for
#endif

#endif

namespace Botan {

/**
* Called when an assertion fails
* Throws an Exception object
*/
BOTAN_NORETURN void BOTAN_PUBLIC_API(2,0)
   assertion_failure(const char* expr_str,
                     const char* assertion_made,
                     const char* func,
                     const char* file,
                     int line);

/**
* Called when an invalid argument is used
* Throws Invalid_Argument
*/
BOTAN_NORETURN void BOTAN_UNSTABLE_API throw_invalid_argument(const char* message,
                                                              const char* func,
                                                              const char* file);


#define BOTAN_ARG_CHECK(expr, msg)                                      \
   do { if(!(expr)) Botan::throw_invalid_argument(msg, __func__, __FILE__); } while(0)

/**
* Called when an invalid state is encountered
* Throws Invalid_State
*/
BOTAN_NORETURN void BOTAN_UNSTABLE_API throw_invalid_state(const char* message,
                                                           const char* func,
                                                           const char* file);


#define BOTAN_STATE_CHECK(expr)                                     \
   do { if(!(expr)) Botan::throw_invalid_state(#expr, __func__, __FILE__); } while(0)

/**
* Make an assertion
*/
#define BOTAN_ASSERT(expr, assertion_made)                \
   do {                                                   \
      if(!(expr))                                         \
         Botan::assertion_failure(#expr,                  \
                                  assertion_made,         \
                                  __func__,               \
                                  __FILE__,               \
                                  __LINE__);              \
   } while(0)

/**
* Make an assertion
*/
#define BOTAN_ASSERT_NOMSG(expr)                          \
   do {                                                   \
      if(!(expr))                                         \
         Botan::assertion_failure(#expr,                  \
                                  "",                     \
                                  __func__,               \
                                  __FILE__,               \
                                  __LINE__);              \
   } while(0)

/**
* Assert that value1 == value2
*/
#define BOTAN_ASSERT_EQUAL(expr1, expr2, assertion_made)   \
   do {                                                    \
     if((expr1) != (expr2))                                \
       Botan::assertion_failure(#expr1 " == " #expr2,      \
                                assertion_made,            \
                                __func__,                  \
                                __FILE__,                  \
                                __LINE__);                 \
   } while(0)

/**
* Assert that expr1 (if true) implies expr2 is also true
*/
#define BOTAN_ASSERT_IMPLICATION(expr1, expr2, msg)        \
   do {                                                    \
     if((expr1) && !(expr2))                               \
       Botan::assertion_failure(#expr1 " implies " #expr2, \
                                msg,                       \
                                __func__,                  \
                                __FILE__,                  \
                                __LINE__);                 \
   } while(0)

/**
* Assert that a pointer is not null
*/
#define BOTAN_ASSERT_NONNULL(ptr)                          \
   do {                                                    \
     if((ptr) == nullptr)                                  \
         Botan::assertion_failure(#ptr " is not null",     \
                                  "",                      \
                                  __func__,                \
                                  __FILE__,                \
                                  __LINE__);               \
   } while(0)

#if defined(BOTAN_ENABLE_DEBUG_ASSERTS)

#define BOTAN_DEBUG_ASSERT(expr) BOTAN_ASSERT_NOMSG(expr)

#else

#define BOTAN_DEBUG_ASSERT(expr) do {} while(0)

#endif

/**
* Mark variable as unused. Takes between 1 and 9 arguments and marks all as unused,
* e.g. BOTAN_UNUSED(a); or BOTAN_UNUSED(x, y, z);
*/
#define _BOTAN_UNUSED_IMPL1(a)                         static_cast<void>(a)
#define _BOTAN_UNUSED_IMPL2(a, b)                      static_cast<void>(a); _BOTAN_UNUSED_IMPL1(b)
#define _BOTAN_UNUSED_IMPL3(a, b, c)                   static_cast<void>(a); _BOTAN_UNUSED_IMPL2(b, c)
#define _BOTAN_UNUSED_IMPL4(a, b, c, d)                static_cast<void>(a); _BOTAN_UNUSED_IMPL3(b, c, d)
#define _BOTAN_UNUSED_IMPL5(a, b, c, d, e)             static_cast<void>(a); _BOTAN_UNUSED_IMPL4(b, c, d, e)
#define _BOTAN_UNUSED_IMPL6(a, b, c, d, e, f)          static_cast<void>(a); _BOTAN_UNUSED_IMPL5(b, c, d, e, f)
#define _BOTAN_UNUSED_IMPL7(a, b, c, d, e, f, g)       static_cast<void>(a); _BOTAN_UNUSED_IMPL6(b, c, d, e, f, g)
#define _BOTAN_UNUSED_IMPL8(a, b, c, d, e, f, g, h)    static_cast<void>(a); _BOTAN_UNUSED_IMPL7(b, c, d, e, f, g, h)
#define _BOTAN_UNUSED_IMPL9(a, b, c, d, e, f, g, h, i) static_cast<void>(a); _BOTAN_UNUSED_IMPL8(b, c, d, e, f, g, h, i)
#define _BOTAN_UNUSED_GET_IMPL(_1, _2, _3, _4, _5, _6, _7, _8, _9, IMPL_NAME, ...) IMPL_NAME

#define BOTAN_UNUSED(...) _BOTAN_UNUSED_GET_IMPL(__VA_ARGS__,                      \
                                                 _BOTAN_UNUSED_IMPL9,              \
                                                 _BOTAN_UNUSED_IMPL8,              \
                                                 _BOTAN_UNUSED_IMPL7,              \
                                                 _BOTAN_UNUSED_IMPL6,              \
                                                 _BOTAN_UNUSED_IMPL5,              \
                                                 _BOTAN_UNUSED_IMPL4,              \
                                                 _BOTAN_UNUSED_IMPL3,              \
                                                 _BOTAN_UNUSED_IMPL2,              \
                                                 _BOTAN_UNUSED_IMPL1,              \
                                                 unused dummy rest value           \
                          ) /* we got an one of _BOTAN_UNUSED_IMPL*, now call it */ (__VA_ARGS__)

}

namespace Botan {

/**
* @mainpage Botan Crypto Library API Reference
*
* <dl>
* <dt>Abstract Base Classes<dd>
*        BlockCipher, HashFunction, KDF, MessageAuthenticationCode, RandomNumberGenerator,
*        StreamCipher, SymmetricAlgorithm, AEAD_Mode, Cipher_Mode
* <dt>Public Key Interface Classes<dd>
*        PK_Key_Agreement, PK_Signer, PK_Verifier, PK_Encryptor, PK_Decryptor
* <dt>Authenticated Encryption Modes<dd>
*        @ref CCM_Mode "CCM", @ref ChaCha20Poly1305_Mode "ChaCha20Poly1305", @ref EAX_Mode "EAX",
*        @ref GCM_Mode "GCM", @ref OCB_Mode "OCB", @ref SIV_Mode "SIV"
* <dt>Block Ciphers<dd>
*        @ref aria.h "ARIA", @ref aes.h "AES", @ref Blowfish, @ref camellia.h "Camellia", @ref Cascade_Cipher "Cascade",
*        @ref CAST_128 "CAST-128", @ref CAST_128 "CAST-256", DES, @ref DESX "DES-X", @ref TripleDES "3DES",
*        @ref GOST_28147_89 "GOST 28147-89", IDEA, KASUMI, Lion, MISTY1, Noekeon, SEED, Serpent, SHACAL2, SM4,
*        @ref Threefish_512 "Threefish", Twofish, XTEA
* <dt>Stream Ciphers<dd>
*        ChaCha, @ref CTR_BE "CTR", OFB, RC4, Salsa20
* <dt>Hash Functions<dd>
*        BLAKE2b, @ref GOST_34_11 "GOST 34.11", @ref Keccak_1600 "Keccak", MD4, MD5, @ref RIPEMD_160 "RIPEMD-160",
*        @ref SHA_160 "SHA-1", @ref SHA_224 "SHA-224", @ref SHA_256 "SHA-256", @ref SHA_384 "SHA-384",
*        @ref SHA_512 "SHA-512", @ref Skein_512 "Skein-512", SM3, Streebog, Tiger, Whirlpool
* <dt>Non-Cryptographic Checksums<dd>
*        Adler32, CRC24, CRC32
* <dt>Message Authentication Codes<dd>
*        @ref CBC_MAC "CBC-MAC", CMAC, HMAC, Poly1305, SipHash, ANSI_X919_MAC
* <dt>Random Number Generators<dd>
*        AutoSeeded_RNG, HMAC_DRBG, Processor_RNG, System_RNG
* <dt>Key Derivation<dd>
*        HKDF, @ref KDF1 "KDF1 (IEEE 1363)", @ref KDF1_18033 "KDF1 (ISO 18033-2)", @ref KDF2 "KDF2 (IEEE 1363)",
*        @ref sp800_108.h "SP800-108", @ref SP800_56C "SP800-56C", @ref PKCS5_PBKDF1 "PBKDF1 (PKCS#5),
*        @ref PKCS5_PBKDF2 "PBKDF2 (PKCS#5)"
* <dt>Password Hashing<dd>
*        @ref argon2.h "Argon2", @ref scrypt.h "scrypt", @ref bcrypt.h "bcrypt", @ref passhash9.h "passhash9"
* <dt>Public Key Cryptosystems<dd>
*        @ref dlies.h "DLIES", @ref ecies.h "ECIES", @ref elgamal.h "ElGamal"
*        @ref rsa.h "RSA", @ref newhope.h "NewHope", @ref mceliece.h "McEliece" and @ref mceies.h "MCEIES",
*        @ref sm2.h "SM2"
* <dt>Public Key Signature Schemes<dd>
*        @ref dsa.h "DSA", @ref ecdsa.h "ECDSA", @ref ecgdsa.h "ECGDSA", @ref eckcdsa.h "ECKCDSA",
*        @ref gost_3410.h "GOST 34.10-2001", @ref sm2.h "SM2", @ref xmss.h "XMSS"
* <dt>Key Agreement<dd>
*        @ref dh.h "DH", @ref ecdh.h "ECDH"
* <dt>Compression<dd>
*        @ref bzip2.h "bzip2", @ref lzma.h "lzma", @ref zlib.h "zlib"
* <dt>TLS<dd>
*        TLS::Client, TLS::Server, TLS::Policy, TLS::Protocol_Version, TLS::Callbacks, TLS::Ciphersuite,
*        TLS::Session, TLS::Session_Manager, Credentials_Manager
* <dt>X.509<dd>
*        X509_Certificate, X509_CRL, X509_CA, Certificate_Extension, PKCS10_Request, X509_Cert_Options,
*        Certificate_Store, Certificate_Store_In_SQL, Certificate_Store_In_SQLite
* </dl>
*/

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::int32_t;
using std::int64_t;
using std::size_t;

/*
* These typedefs are no longer used within the library headers
* or code. They are kept only for compatability with software
* written against older versions.
*/
using byte   = std::uint8_t;
using u16bit = std::uint16_t;
using u32bit = std::uint32_t;
using u64bit = std::uint64_t;
using s32bit = std::int32_t;

#if (BOTAN_MP_WORD_BITS == 32)
  typedef uint32_t word;
#elif (BOTAN_MP_WORD_BITS == 64)
  typedef uint64_t word;
#else
  #error BOTAN_MP_WORD_BITS must be 32 or 64
#endif

/*
* Should this assert fail on your system please contact the developers
* for assistance in porting.
*/
static_assert(sizeof(std::size_t) == 8 || sizeof(std::size_t) == 4,
              "This platform has an unexpected size for size_t");

}

namespace Botan {

/**
* Allocate a memory buffer by some method. This should only be used for
* primitive types (uint8_t, uint32_t, etc).
*
* @param elems the number of elements
* @param elem_size the size of each element
* @return pointer to allocated and zeroed memory, or throw std::bad_alloc on failure
*/
BOTAN_PUBLIC_API(2,3) BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size);

/**
* Free a pointer returned by allocate_memory
* @param p the pointer returned by allocate_memory
* @param elems the number of elements, as passed to allocate_memory
* @param elem_size the size of each element, as passed to allocate_memory
*/
BOTAN_PUBLIC_API(2,3) void deallocate_memory(void* p, size_t elems, size_t elem_size);

/**
* Ensure the allocator is initialized
*/
void BOTAN_UNSTABLE_API initialize_allocator();

class Allocator_Initializer
   {
   public:
      Allocator_Initializer() { initialize_allocator(); }
   };

/**
* Scrub memory contents in a way that a compiler should not elide,
* using some system specific technique. Note that this function might
* not zero the memory (for example, in some hypothetical
* implementation it might combine the memory contents with the output
* of a system PRNG), but if you can detect any difference in behavior
* at runtime then the clearing is side-effecting and you can just
* use `clear_mem`.
*
* Use this function to scrub memory just before deallocating it, or on
* a stack buffer before returning from the function.
*
* @param ptr a pointer to memory to scrub
* @param n the number of bytes pointed to by ptr
*/
BOTAN_PUBLIC_API(2,0) void secure_scrub_memory(void* ptr, size_t n);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return 0xFF iff x[i] == y[i] forall i in [0...n) or 0x00 otherwise
*/
BOTAN_PUBLIC_API(2,9) uint8_t ct_compare_u8(const uint8_t x[],
                                            const uint8_t y[],
                                            size_t len);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return true iff x[i] == y[i] forall i in [0...n)
*/
inline bool constant_time_compare(const uint8_t x[],
                                  const uint8_t y[],
                                  size_t len)
   {
   return ct_compare_u8(x, y, len) == 0xFF;
   }

/**
* Zero out some bytes. Warning: use secure_scrub_memory instead if the
* memory is about to be freed or otherwise the compiler thinks it can
* elide the writes.
*
* @param ptr a pointer to memory to zero
* @param bytes the number of bytes to zero in ptr
*/
inline void clear_bytes(void* ptr, size_t bytes)
   {
   if(bytes > 0)
      {
      std::memset(ptr, 0, bytes);
      }
   }

/**
* Zero memory before use. This simply calls memset and should not be
* used in cases where the compiler cannot see the call as a
* side-effecting operation (for example, if calling clear_mem before
* deallocating memory, the compiler would be allowed to omit the call
* to memset entirely under the as-if rule.)
*
* @param ptr a pointer to an array of Ts to zero
* @param n the number of Ts pointed to by ptr
*/
template<typename T> inline void clear_mem(T* ptr, size_t n)
   {
   clear_bytes(ptr, sizeof(T)*n);
   }

// is_trivially_copyable is missing in g++ < 5.0
#if (BOTAN_GCC_VERSION > 0 && BOTAN_GCC_VERSION < 500)
#define BOTAN_IS_TRIVIALLY_COPYABLE(T) true
#else
#define BOTAN_IS_TRIVIALLY_COPYABLE(T) std::is_trivially_copyable<T>::value
#endif

/**
* Copy memory
* @param out the destination array
* @param in the source array
* @param n the number of elements of in/out
*/
template<typename T> inline void copy_mem(T* out, const T* in, size_t n)
   {
   static_assert(std::is_trivial<typename std::decay<T>::type>::value, "");
   BOTAN_ASSERT_IMPLICATION(n > 0, in != nullptr && out != nullptr,
                            "If n > 0 then args are not null");

   if(in != nullptr && out != nullptr && n > 0)
      {
      std::memmove(out, in, sizeof(T)*n);
      }
   }

template<typename T> inline void typecast_copy(uint8_t out[], T in[], size_t N)
   {
   static_assert(BOTAN_IS_TRIVIALLY_COPYABLE(T), "");
   std::memcpy(out, in, sizeof(T)*N);
   }

template<typename T> inline void typecast_copy(T out[], const uint8_t in[], size_t N)
   {
   static_assert(std::is_trivial<T>::value, "");
   std::memcpy(out, in, sizeof(T)*N);
   }

template<typename T> inline void typecast_copy(uint8_t out[], T in)
   {
   typecast_copy(out, &in, 1);
   }

template<typename T> inline void typecast_copy(T& out, const uint8_t in[])
   {
   static_assert(std::is_trivial<typename std::decay<T>::type>::value, "");
   typecast_copy(&out, in, 1);
   }

template <class To, class From> inline To typecast_copy(const From *src) noexcept
   {
   static_assert(BOTAN_IS_TRIVIALLY_COPYABLE(From) && std::is_trivial<To>::value, "");
   To dst;
   std::memcpy(&dst, src, sizeof(To));
   return dst;
   }

/**
* Set memory to a fixed value
* @param ptr a pointer to an array of bytes
* @param n the number of Ts pointed to by ptr
* @param val the value to set each byte to
*/
inline void set_mem(uint8_t* ptr, size_t n, uint8_t val)
   {
   if(n > 0)
      {
      std::memset(ptr, val, n);
      }
   }

inline const uint8_t* cast_char_ptr_to_uint8(const char* s)
   {
   return reinterpret_cast<const uint8_t*>(s);
   }

inline const char* cast_uint8_ptr_to_char(const uint8_t* b)
   {
   return reinterpret_cast<const char*>(b);
   }

inline uint8_t* cast_char_ptr_to_uint8(char* s)
   {
   return reinterpret_cast<uint8_t*>(s);
   }

inline char* cast_uint8_ptr_to_char(uint8_t* b)
   {
   return reinterpret_cast<char*>(b);
   }

/**
* Memory comparison, input insensitive
* @param p1 a pointer to an array
* @param p2 a pointer to another array
* @param n the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
template<typename T> inline bool same_mem(const T* p1, const T* p2, size_t n)
   {
   volatile T difference = 0;

   for(size_t i = 0; i != n; ++i)
      difference |= (p1[i] ^ p2[i]);

   return difference == 0;
   }

template<typename T, typename Alloc>
size_t buffer_insert(std::vector<T, Alloc>& buf,
                     size_t buf_offset,
                     const T input[],
                     size_t input_length)
   {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
   if(to_copy > 0)
      {
      copy_mem(&buf[buf_offset], input, to_copy);
      }
   return to_copy;
   }

template<typename T, typename Alloc, typename Alloc2>
size_t buffer_insert(std::vector<T, Alloc>& buf,
                     size_t buf_offset,
                     const std::vector<T, Alloc2>& input)
   {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input.size(), buf.size() - buf_offset);
   if(to_copy > 0)
      {
      copy_mem(&buf[buf_offset], input.data(), to_copy);
      }
   return to_copy;
   }

/**
* XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
* @param out the input/output buffer
* @param in the read-only input buffer
* @param length the length of the buffers
*/
inline void xor_buf(uint8_t out[],
                    const uint8_t in[],
                    size_t length)
   {
   const size_t blocks = length - (length % 32);

   for(size_t i = 0; i != blocks; i += 32)
      {
      uint64_t x[4];
      uint64_t y[4];

      typecast_copy(x, out + i, 4);
      typecast_copy(y, in + i, 4);

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(out + i, x, 4);
      }

   for(size_t i = blocks; i != length; ++i)
      {
      out[i] ^= in[i];
      }
   }

/**
* XOR arrays. Postcondition out[i] = in[i] ^ in2[i] forall i = 0...length
* @param out the output buffer
* @param in the first input buffer
* @param in2 the second output buffer
* @param length the length of the three buffers
*/
inline void xor_buf(uint8_t out[],
                    const uint8_t in[],
                    const uint8_t in2[],
                    size_t length)
   {
   const size_t blocks = length - (length % 32);

   for(size_t i = 0; i != blocks; i += 32)
      {
      uint64_t x[4];
      uint64_t y[4];

      typecast_copy(x, in + i, 4);
      typecast_copy(y, in2 + i, 4);

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(out + i, x, 4);
      }

   for(size_t i = blocks; i != length; ++i)
      {
      out[i] = in[i] ^ in2[i];
      }
   }

template<typename Alloc, typename Alloc2>
void xor_buf(std::vector<uint8_t, Alloc>& out,
             const std::vector<uint8_t, Alloc2>& in,
             size_t n)
   {
   xor_buf(out.data(), in.data(), n);
   }

template<typename Alloc>
void xor_buf(std::vector<uint8_t, Alloc>& out,
             const uint8_t* in,
             size_t n)
   {
   xor_buf(out.data(), in, n);
   }

template<typename Alloc, typename Alloc2>
void xor_buf(std::vector<uint8_t, Alloc>& out,
             const uint8_t* in,
             const std::vector<uint8_t, Alloc2>& in2,
             size_t n)
   {
   xor_buf(out.data(), in, in2.data(), n);
   }

template<typename Alloc, typename Alloc2>
std::vector<uint8_t, Alloc>&
operator^=(std::vector<uint8_t, Alloc>& out,
           const std::vector<uint8_t, Alloc2>& in)
   {
   if(out.size() < in.size())
      out.resize(in.size());

   xor_buf(out.data(), in.data(), in.size());
   return out;
   }

}

namespace Botan {

template<typename T>
class secure_allocator
   {
   public:
      /*
      * Assert exists to prevent someone from doing something that will
      * probably crash anyway (like secure_vector<non_POD_t> where ~non_POD_t
      * deletes a member pointer which was zeroed before it ran).
      * MSVC in debug mode uses non-integral proxy types in container types
      * like std::vector, thus we disable the check there.
      */
#if !defined(_ITERATOR_DEBUG_LEVEL) || _ITERATOR_DEBUG_LEVEL == 0
      static_assert(std::is_integral<T>::value, "secure_allocator supports only integer types");
#endif

      typedef T          value_type;
      typedef std::size_t size_type;

      secure_allocator() noexcept = default;
      secure_allocator(const secure_allocator&) noexcept = default;
      secure_allocator& operator=(const secure_allocator&) noexcept = default;
      ~secure_allocator() noexcept = default;

      template<typename U>
      secure_allocator(const secure_allocator<U>&) noexcept {}

      T* allocate(std::size_t n)
         {
         return static_cast<T*>(allocate_memory(n, sizeof(T)));
         }

      void deallocate(T* p, std::size_t n)
         {
         deallocate_memory(p, n, sizeof(T));
         }
   };

template<typename T, typename U> inline bool
operator==(const secure_allocator<T>&, const secure_allocator<U>&)
   { return true; }

template<typename T, typename U> inline bool
operator!=(const secure_allocator<T>&, const secure_allocator<U>&)
   { return false; }

template<typename T> using secure_vector = std::vector<T, secure_allocator<T>>;
template<typename T> using secure_deque = std::deque<T, secure_allocator<T>>;

// For better compatibility with 1.10 API
template<typename T> using SecureVector = secure_vector<T>;

template<typename T>
std::vector<T> unlock(const secure_vector<T>& in)
   {
   return std::vector<T>(in.begin(), in.end());
   }

template<typename T, typename Alloc, typename Alloc2>
std::vector<T, Alloc>&
operator+=(std::vector<T, Alloc>& out,
           const std::vector<T, Alloc2>& in)
   {
   out.insert(out.end(), in.begin(), in.end());
   return out;
   }

template<typename T, typename Alloc>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out, T in)
   {
   out.push_back(in);
   return out;
   }

template<typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out,
                                  const std::pair<const T*, L>& in)
   {
   out.insert(out.end(), in.first, in.first + in.second);
   return out;
   }

template<typename T, typename Alloc, typename L>
std::vector<T, Alloc>& operator+=(std::vector<T, Alloc>& out,
                                  const std::pair<T*, L>& in)
   {
   out.insert(out.end(), in.first, in.first + in.second);
   return out;
   }

/**
* Zeroise the values; length remains unchanged
* @param vec the vector to zeroise
*/
template<typename T, typename Alloc>
void zeroise(std::vector<T, Alloc>& vec)
   {
   clear_mem(vec.data(), vec.size());
   }

/**
* Zeroise the values then free the memory
* @param vec the vector to zeroise and free
*/
template<typename T, typename Alloc>
void zap(std::vector<T, Alloc>& vec)
   {
   zeroise(vec);
   vec.clear();
   vec.shrink_to_fit();
   }

}

namespace Botan {

/**
* Octet String
*/
class BOTAN_PUBLIC_API(2,0) OctetString final
   {
   public:
      /**
      * @return size of this octet string in bytes
      */
      size_t length() const { return m_data.size(); }
      size_t size() const { return m_data.size(); }

      /**
      * @return this object as a secure_vector<uint8_t>
      */
      secure_vector<uint8_t> bits_of() const { return m_data; }

      /**
      * @return start of this string
      */
      const uint8_t* begin() const { return m_data.data(); }

      /**
      * @return end of this string
      */
      const uint8_t* end() const   { return begin() + m_data.size(); }

      /**
      * @return this encoded as hex
      */
      std::string to_string() const;

      std::string BOTAN_DEPRECATED("Use OctetString::to_string") as_string() const
         {
         return this->to_string();
         }

      /**
      * XOR the contents of another octet string into this one
      * @param other octet string
      * @return reference to this
      */
      OctetString& operator^=(const OctetString& other);

      /**
      * Force to have odd parity
      */
      void set_odd_parity();

      /**
      * Create a new OctetString
      * @param str is a hex encoded string
      */
      explicit OctetString(const std::string& str = "");

      /**
      * Create a new random OctetString
      * @param rng is a random number generator
      * @param len is the desired length in bytes
      */
      OctetString(class RandomNumberGenerator& rng, size_t len);

      /**
      * Create a new OctetString
      * @param in is an array
      * @param len is the length of in in bytes
      */
      OctetString(const uint8_t in[], size_t len);

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      OctetString(const secure_vector<uint8_t>& in) : m_data(in) {}

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      OctetString(const std::vector<uint8_t>& in) : m_data(in.begin(), in.end()) {}

   private:
      secure_vector<uint8_t> m_data;
   };

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is equal to y
*/
BOTAN_PUBLIC_API(2,0) bool operator==(const OctetString& x,
                          const OctetString& y);

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is not equal to y
*/
BOTAN_PUBLIC_API(2,0) bool operator!=(const OctetString& x,
                          const OctetString& y);

/**
* Concatenate two strings
* @param x an octet string
* @param y an octet string
* @return x concatenated with y
*/
BOTAN_PUBLIC_API(2,0) OctetString operator+(const OctetString& x,
                                const OctetString& y);

/**
* XOR two strings
* @param x an octet string
* @param y an octet string
* @return x XORed with y
*/
BOTAN_PUBLIC_API(2,0) OctetString operator^(const OctetString& x,
                                const OctetString& y);


/**
* Alternate name for octet string showing intent to use as a key
*/
using SymmetricKey = OctetString;

/**
* Alternate name for octet string showing intent to use as an IV
*/
using InitializationVector = OctetString;

}

namespace Botan {

/**
* Represents the length requirements on an algorithm key
*/
class BOTAN_PUBLIC_API(2,0) Key_Length_Specification final
   {
   public:
      /**
      * Constructor for fixed length keys
      * @param keylen the supported key length
      */
      explicit Key_Length_Specification(size_t keylen) :
         m_min_keylen(keylen),
         m_max_keylen(keylen),
         m_keylen_mod(1)
         {
         }

      /**
      * Constructor for variable length keys
      * @param min_k the smallest supported key length
      * @param max_k the largest supported key length
      * @param k_mod the number of bytes the key must be a multiple of
      */
      Key_Length_Specification(size_t min_k,
                               size_t max_k,
                               size_t k_mod = 1) :
         m_min_keylen(min_k),
         m_max_keylen(max_k ? max_k : min_k),
         m_keylen_mod(k_mod)
         {
         }

      /**
      * @param length is a key length in bytes
      * @return true iff this length is a valid length for this algo
      */
      bool valid_keylength(size_t length) const
         {
         return ((length >= m_min_keylen) &&
                 (length <= m_max_keylen) &&
                 (length % m_keylen_mod == 0));
         }

      /**
      * @return minimum key length in bytes
      */
      size_t minimum_keylength() const
         {
         return m_min_keylen;
         }

      /**
      * @return maximum key length in bytes
      */
      size_t maximum_keylength() const
         {
         return m_max_keylen;
         }

      /**
      * @return key length multiple in bytes
      */
      size_t keylength_multiple() const
         {
         return m_keylen_mod;
         }

      /*
      * Multiplies all length requirements with the given factor
      * @param n the multiplication factor
      * @return a key length specification multiplied by the factor
      */
      Key_Length_Specification multiple(size_t n) const
         {
         return Key_Length_Specification(n * m_min_keylen,
                                         n * m_max_keylen,
                                         n * m_keylen_mod);
         }

   private:
      size_t m_min_keylen, m_max_keylen, m_keylen_mod;
   };

/**
* This class represents a symmetric algorithm object.
*/
class BOTAN_PUBLIC_API(2,0) SymmetricAlgorithm
   {
   public:
      virtual ~SymmetricAlgorithm() {}

      /**
      * Reset the state.
      */
      virtual void clear() = 0;

      /**
      * @return object describing limits on key size
      */
      virtual Key_Length_Specification key_spec() const = 0;

      /**
      * @return maximum allowed key length
      */
      size_t maximum_keylength() const
         {
         return key_spec().maximum_keylength();
         }

      /**
      * @return minimum allowed key length
      */
      size_t minimum_keylength() const
         {
         return key_spec().minimum_keylength();
         }

      /**
      * Check whether a given key length is valid for this algorithm.
      * @param length the key length to be checked.
      * @return true if the key length is valid.
      */
      bool valid_keylength(size_t length) const
         {
         return key_spec().valid_keylength(length);
         }

      /**
      * Set the symmetric key of this object.
      * @param key the SymmetricKey to be set.
      */
      void set_key(const SymmetricKey& key)
         {
         set_key(key.begin(), key.length());
         }

      template<typename Alloc>
      void set_key(const std::vector<uint8_t, Alloc>& key)
         {
         set_key(key.data(), key.size());
         }

      /**
      * Set the symmetric key of this object.
      * @param key the to be set as a byte array.
      * @param length in bytes of key param
      */
      void set_key(const uint8_t key[], size_t length);

      /**
      * @return the algorithm name
      */
      virtual std::string name() const = 0;

   protected:
      void verify_key_set(bool cond) const
         {
         if(cond == false)
            throw_key_not_set_error();
         }

   private:
      void throw_key_not_set_error() const;

      /**
      * Run the key schedule
      * @param key the key
      * @param length of key
      */
      virtual void key_schedule(const uint8_t key[], size_t length) = 0;
   };

}

namespace Botan {

/**
* This class represents a block cipher object.
*/
class BOTAN_PUBLIC_API(2,0) BlockCipher : public SymmetricAlgorithm
   {
   public:

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<BlockCipher>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<BlockCipher>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * @return block size of this algorithm
      */
      virtual size_t block_size() const = 0;

      /**
      * @return native parallelism of this cipher in blocks
      */
      virtual size_t parallelism() const { return 1; }

      /**
      * @return prefererred parallelism of this cipher in bytes
      */
      size_t parallel_bytes() const
         {
         return parallelism() * block_size() * BOTAN_BLOCK_CIPHER_PAR_MULT;
         }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the encrypted block.
      * Must be of length block_size().
      */
      void encrypt(const uint8_t in[], uint8_t out[]) const
         { encrypt_n(in, out, 1); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the decrypted block.
      * Must be of length block_size().
      */
      void decrypt(const uint8_t in[], uint8_t out[]) const
         { decrypt_n(in, out, 1); }

      /**
      * Encrypt a block.
      * @param block the plaintext block to be encrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void encrypt(uint8_t block[]) const { encrypt_n(block, block, 1); }

      /**
      * Decrypt a block.
      * @param block the ciphertext block to be decrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void decrypt(uint8_t block[]) const { decrypt_n(block, block, 1); }

      /**
      * Encrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      template<typename Alloc>
      void encrypt(std::vector<uint8_t, Alloc>& block) const
         {
         return encrypt_n(block.data(), block.data(), block.size() / block_size());
         }

      /**
      * Decrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      template<typename Alloc>
      void decrypt(std::vector<uint8_t, Alloc>& block) const
         {
         return decrypt_n(block.data(), block.data(), block.size() / block_size());
         }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      template<typename Alloc, typename Alloc2>
      void encrypt(const std::vector<uint8_t, Alloc>& in,
                   std::vector<uint8_t, Alloc2>& out) const
         {
         return encrypt_n(in.data(), out.data(), in.size() / block_size());
         }

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      template<typename Alloc, typename Alloc2>
      void decrypt(const std::vector<uint8_t, Alloc>& in,
                   std::vector<uint8_t, Alloc2>& out) const
         {
         return decrypt_n(in.data(), out.data(), in.size() / block_size());
         }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void encrypt_n(const uint8_t in[], uint8_t out[],
                             size_t blocks) const = 0;

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void decrypt_n(const uint8_t in[], uint8_t out[],
                             size_t blocks) const = 0;

      virtual void encrypt_n_xex(uint8_t data[],
                                 const uint8_t mask[],
                                 size_t blocks) const
         {
         const size_t BS = block_size();
         xor_buf(data, mask, blocks * BS);
         encrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      virtual void decrypt_n_xex(uint8_t data[],
                                 const uint8_t mask[],
                                 size_t blocks) const
         {
         const size_t BS = block_size();
         xor_buf(data, mask, blocks * BS);
         decrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual BlockCipher* clone() const = 0;

      virtual ~BlockCipher() {}
   };

/**
* Tweakable block ciphers allow setting a tweak which is a non-keyed
* value which affects the encryption/decryption operation.
*/
class BOTAN_PUBLIC_API(2,8) Tweakable_Block_Cipher : public BlockCipher
   {
   public:
      /**
      * Set the tweak value. This must be called after setting a key. The value
      * persists until either set_tweak, set_key, or clear is called.
      * Different algorithms support different tweak length(s). If called with
      * an unsupported length, Invalid_Argument will be thrown.
      */
      virtual void set_tweak(const uint8_t tweak[], size_t len) = 0;
   };

/**
* Represents a block cipher with a single fixed block size
*/
template<size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1, typename BaseClass = BlockCipher>
class Block_Cipher_Fixed_Params : public BaseClass
   {
   public:
      enum { BLOCK_SIZE = BS };
      size_t block_size() const final override { return BS; }

      // override to take advantage of compile time constant block size
      void encrypt_n_xex(uint8_t data[],
                         const uint8_t mask[],
                         size_t blocks) const final override
         {
         xor_buf(data, mask, blocks * BS);
         this->encrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      void decrypt_n_xex(uint8_t data[],
                         const uint8_t mask[],
                         size_t blocks) const final override
         {
         xor_buf(data, mask, blocks * BS);
         this->decrypt_n(data, data, blocks);
         xor_buf(data, mask, blocks * BS);
         }

      Key_Length_Specification key_spec() const final override
         {
         return Key_Length_Specification(KMIN, KMAX, KMOD);
         }
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(aes.h)

namespace Botan {

/**
* AES-128
*/
class BOTAN_PUBLIC_API(2,0) AES_128 final : public Block_Cipher_Fixed_Params<16, 16>
   {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;
      std::string name() const override { return "AES-128"; }
      BlockCipher* clone() const override { return new AES_128; }
      size_t parallelism() const override;

   private:
      void key_schedule(const uint8_t key[], size_t length) override;

#if defined(BOTAN_HAS_AES_VPERM)
      void vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_NI)
      void aesni_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
      void hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      secure_vector<uint32_t> m_EK, m_DK;
   };

/**
* AES-192
*/
class BOTAN_PUBLIC_API(2,0) AES_192 final : public Block_Cipher_Fixed_Params<16, 24>
   {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;
      std::string name() const override { return "AES-192"; }
      BlockCipher* clone() const override { return new AES_192; }
      size_t parallelism() const override;

   private:
#if defined(BOTAN_HAS_AES_VPERM)
      void vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_NI)
      void aesni_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
      void hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      void key_schedule(const uint8_t key[], size_t length) override;

      secure_vector<uint32_t> m_EK, m_DK;
   };

/**
* AES-256
*/
class BOTAN_PUBLIC_API(2,0) AES_256 final : public Block_Cipher_Fixed_Params<16, 32>
   {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;

      std::string name() const override { return "AES-256"; }
      BlockCipher* clone() const override { return new AES_256; }
      size_t parallelism() const override;

   private:
#if defined(BOTAN_HAS_AES_VPERM)
      void vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_NI)
      void aesni_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
      void hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      void key_schedule(const uint8_t key[], size_t length) override;

      secure_vector<uint32_t> m_EK, m_DK;
   };

}

namespace Botan {

/**
* Different types of errors that might occur
*/
enum class ErrorType {
   /** Some unknown error */
   Unknown = 1,
   /** An error while calling a system interface */
   SystemError,
   /** An operation seems valid, but not supported by the current version */
   NotImplemented,
   /** Memory allocation failure */
   OutOfMemory,
   /** An internal error occurred */
   InternalError,
   /** An I/O error occurred */
   IoError,

   /** Invalid object state */
   InvalidObjectState = 100,
   /** A key was not set on an object when this is required */
   KeyNotSet,
   /** The application provided an argument which is invalid */
   InvalidArgument,
   /** A key with invalid length was provided */
   InvalidKeyLength,
   /** A nonce with invalid length was provided */
   InvalidNonceLength,
   /** An object type was requested but cannot be found */
   LookupError,
   /** Encoding a message or datum failed */
   EncodingFailure,
   /** Decoding a message or datum failed */
   DecodingFailure,
   /** A TLS error (error_code will be the alert type) */
   TLSError,
   /** An error during an HTTP operation */
   HttpError,
   /** A message with an invalid authentication tag was detected */
   InvalidTag,
   /** An error during Roughtime validation */
   RoughtimeError,

   /** An error when calling OpenSSL */
   OpenSSLError = 200,
   /** An error when interacting with CommonCrypto API */
   CommonCryptoError,
   /** An error when interacting with a PKCS11 device */
   Pkcs11Error,
   /** An error when interacting with a TPM device */
   TPMError,
   /** An error when interacting with a database */
   DatabaseError,

   /** An error when interacting with zlib */
   ZlibError = 300,
   /** An error when interacting with bzip2 */
   Bzip2Error,
   /** An error when interacting with lzma */
   LzmaError,

};

//! \brief Convert an ErrorType to string
std::string BOTAN_PUBLIC_API(2,11) to_string(ErrorType type);

/**
* Base class for all exceptions thrown by the library
*/
class BOTAN_PUBLIC_API(2,0) Exception : public std::exception
   {
   public:
      /**
      * Return a descriptive string which is hopefully comprehensible to
      * a developer. It will likely not be useful for an end user.
      *
      * The string has no particular format, and the content of exception
      * messages may change from release to release. Thus the main use of this
      * function is for logging or debugging.
      */
      const char* what() const noexcept override { return m_msg.c_str(); }

      /**
      * Return the "type" of error which occurred.
      */
      virtual ErrorType error_type() const noexcept { return Botan::ErrorType::Unknown; }

      /**
      * Return an error code associated with this exception, or otherwise 0.
      *
      * The domain of this error varies depending on the source, for example on
      * POSIX systems it might be errno, while on a Windows system it might be
      * the result of GetLastError or WSAGetLastError. For error_type() is
      * OpenSSLError, it will (if nonzero) be an OpenSSL error code from
      * ERR_get_error.
      */
      virtual int error_code() const noexcept { return 0; }

      /**
      * Avoid throwing base Exception, use a subclass
      */
      explicit Exception(const std::string& msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(const char* prefix, const std::string& msg);

      /**
      * Avoid throwing base Exception, use a subclass
      */
      Exception(const std::string& msg, const std::exception& e);

   private:
      std::string m_msg;
   };

/**
* An invalid argument was provided to an API call.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Argument : public Exception
   {
   public:
      explicit Invalid_Argument(const std::string& msg);

      explicit Invalid_Argument(const std::string& msg, const std::string& where);

      Invalid_Argument(const std::string& msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidArgument; }
   };

/**
* An invalid key length was used
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Key_Length final : public Invalid_Argument
   {
   public:
      Invalid_Key_Length(const std::string& name, size_t length);
      ErrorType error_type() const noexcept override { return ErrorType::InvalidKeyLength; }
   };

/**
* An invalid nonce length was used
*/
class BOTAN_PUBLIC_API(2,0) Invalid_IV_Length final : public Invalid_Argument
   {
   public:
      Invalid_IV_Length(const std::string& mode, size_t bad_len);
      ErrorType error_type() const noexcept override { return ErrorType::InvalidNonceLength; }
   };

/**
* Invalid_Algorithm_Name Exception
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Algorithm_Name final : public Invalid_Argument
   {
   public:
      explicit Invalid_Algorithm_Name(const std::string& name);
   };

/**
* Encoding_Error Exception
*
* This exception derives from Invalid_Argument for historical reasons, and it
* does not make any real sense for it to do so. In a future major release this
* exception type will derive directly from Exception instead.
*/
class BOTAN_PUBLIC_API(2,0) Encoding_Error final : public Invalid_Argument
   {
   public:
      explicit Encoding_Error(const std::string& name);

      ErrorType error_type() const noexcept override { return ErrorType::EncodingFailure; }
   };

/**
* A decoding error occurred.
*
* This exception derives from Invalid_Argument for historical reasons, and it
* does not make any real sense for it to do so. In a future major release this
* exception type will derive directly from Exception instead.
*/
class BOTAN_PUBLIC_API(2,0) Decoding_Error : public Invalid_Argument
   {
   public:
      explicit Decoding_Error(const std::string& name);

      Decoding_Error(const std::string& name, const char* exception_message);

      Decoding_Error(const std::string& msg, const std::exception& e);

      ErrorType error_type() const noexcept override { return ErrorType::DecodingFailure; }
   };

/**
* Invalid state was encountered. A request was made on an object while the
* object was in a state where the operation cannot be performed.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_State : public Exception
   {
   public:
      explicit Invalid_State(const std::string& err) : Exception(err) {}

      ErrorType error_type() const noexcept override { return ErrorType::InvalidObjectState; }
   };

/**
* A PRNG was called on to produce output while still unseeded
*/
class BOTAN_PUBLIC_API(2,0) PRNG_Unseeded final : public Invalid_State
   {
   public:
      explicit PRNG_Unseeded(const std::string& algo);
   };

/**
* The key was not set on an object. This occurs with symmetric objects where
* an operation which requires the key is called prior to set_key being called.
*/
class BOTAN_PUBLIC_API(2,4) Key_Not_Set : public Invalid_State
   {
   public:
      explicit Key_Not_Set(const std::string& algo);

      ErrorType error_type() const noexcept override { return ErrorType::KeyNotSet; }
   };

/**
* A request was made for some kind of object which could not be located
*/
class BOTAN_PUBLIC_API(2,0) Lookup_Error : public Exception
   {
   public:
      explicit Lookup_Error(const std::string& err) : Exception(err) {}

      Lookup_Error(const std::string& type,
                   const std::string& algo,
                   const std::string& provider);

      ErrorType error_type() const noexcept override { return ErrorType::LookupError; }
   };

/**
* Algorithm_Not_Found Exception
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2,0) Algorithm_Not_Found final : public Lookup_Error
   {
   public:
      explicit Algorithm_Not_Found(const std::string& name);
   };

/**
* Provider_Not_Found is thrown when a specific provider was requested
* but that provider is not available.
*
* @warning This exception type will be removed in the future. Instead
* just catch Lookup_Error.
*/
class BOTAN_PUBLIC_API(2,0) Provider_Not_Found final : public Lookup_Error
   {
   public:
      Provider_Not_Found(const std::string& algo, const std::string& provider);
   };

/**
* An AEAD or MAC check detected a message modification
*
* In versions before 2.10, Invalid_Authentication_Tag was named
* Integrity_Failure, it was renamed to make its usage more clear.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_Authentication_Tag final : public Exception
   {
   public:
      explicit Invalid_Authentication_Tag(const std::string& msg);

      ErrorType error_type() const noexcept override { return ErrorType::InvalidTag; }
   };

/**
* For compatability with older versions
*/
typedef Invalid_Authentication_Tag Integrity_Failure;

/**
* An error occurred while operating on an IO stream
*/
class BOTAN_PUBLIC_API(2,0) Stream_IO_Error final : public Exception
   {
   public:
      explicit Stream_IO_Error(const std::string& err);

      ErrorType error_type() const noexcept override { return ErrorType::IoError; }
   };

/**
* System_Error
*
* This exception is thrown in the event of an error related to interacting
* with the operating system.
*
* This exception type also (optionally) captures an integer error code eg
* POSIX errno or Windows GetLastError.
*/
class BOTAN_PUBLIC_API(2,9) System_Error : public Exception
   {
   public:
      System_Error(const std::string& msg) : Exception(msg), m_error_code(0) {}

      System_Error(const std::string& msg, int err_code);

      ErrorType error_type() const noexcept override { return ErrorType::SystemError; }

      int error_code() const noexcept override { return m_error_code; }

   private:
      int m_error_code;
   };

/**
* An internal error occurred. If observed, please file a bug.
*/
class BOTAN_PUBLIC_API(2,0) Internal_Error : public Exception
   {
   public:
      explicit Internal_Error(const std::string& err);

      ErrorType error_type() const noexcept override { return ErrorType::InternalError; }
   };

/**
* Not Implemented Exception
*
* This is thrown in the situation where a requested operation is
* logically valid but is not implemented by this version of the library.
*/
class BOTAN_PUBLIC_API(2,0) Not_Implemented final : public Exception
   {
   public:
      explicit Not_Implemented(const std::string& err);

      ErrorType error_type() const noexcept override { return ErrorType::NotImplemented; }
   };

/*
   The following exception types are still in use for compatability reasons,
   but are deprecated and will be removed in a future major release.
   Instead catch the base class.
*/

/**
* An invalid OID string was used.
*
* This exception will be removed in a future major release.
*/
class BOTAN_PUBLIC_API(2,0) Invalid_OID final : public Decoding_Error
   {
   public:
      explicit Invalid_OID(const std::string& oid);
   };

/*
   The following exception types are deprecated, no longer used,
   and will be removed in a future major release
*/

/**
* Self Test Failure Exception
*
* This exception is no longer used. It will be removed in a future major release.
*/
class BOTAN_PUBLIC_API(2,0) Self_Test_Failure final : public Internal_Error
   {
   public:
      BOTAN_DEPRECATED("no longer used") explicit Self_Test_Failure(const std::string& err);
   };

/**
* No_Provider_Found Exception
*
* This exception is no longer used. It will be removed in a future major release.
*/
class BOTAN_PUBLIC_API(2,0) No_Provider_Found final : public Exception
   {
   public:
      BOTAN_DEPRECATED("no longer used") explicit No_Provider_Found(const std::string& name);
   };

/**
* Policy_Violation Exception
*
* This exception is no longer used. It will be removed in a future major release.
*/
class BOTAN_PUBLIC_API(2,0) Policy_Violation final : public Invalid_State
   {
   public:
      BOTAN_DEPRECATED("no longer used") explicit Policy_Violation(const std::string& err);
   };

/**
* Unsupported_Argument Exception
*
* An argument that is invalid because it is not supported by Botan.
* It might or might not be valid in another context like a standard.
*
* This exception is no longer used, instead Not_Implemented is thrown.
* It will be removed in a future major release.
*/
class BOTAN_PUBLIC_API(2,0) Unsupported_Argument final : public Invalid_Argument
   {
   public:
      BOTAN_DEPRECATED("no longer used") explicit Unsupported_Argument(const std::string& msg) : Invalid_Argument(msg) {}
   };

template<typename E, typename... Args>
inline void do_throw_error(const char* file, int line, const char* func, Args... args)
   {
   throw E(file, line, func, args...);
   }

}

#if defined(BOTAN_TARGET_OS_HAS_THREADS)


namespace Botan {

template<typename T> using lock_guard_type = std::lock_guard<T>;
typedef std::mutex mutex_type;
typedef std::recursive_mutex recursive_mutex_type;

}

#else

// No threads

namespace Botan {

template<typename Mutex>
class lock_guard final
   {
   public:
      explicit lock_guard(Mutex& m) : m_mutex(m)
         { m_mutex.lock(); }

      ~lock_guard() { m_mutex.unlock(); }

      lock_guard(const lock_guard& other) = delete;
      lock_guard& operator=(const lock_guard& other) = delete;
   private:
      Mutex& m_mutex;
   };

class noop_mutex final
   {
   public:
      void lock() {}
      void unlock() {}
   };

typedef noop_mutex mutex_type;
typedef noop_mutex recursive_mutex_type;
template<typename T> using lock_guard_type = lock_guard<T>;

}

#endif

namespace Botan {

class Entropy_Sources;

/**
* An interface to a cryptographic random number generator
*/
class BOTAN_PUBLIC_API(2,0) RandomNumberGenerator
   {
   public:
      virtual ~RandomNumberGenerator() {}

      RandomNumberGenerator() = default;

      /*
      * Never copy a RNG, create a new one
      */
      RandomNumberGenerator(const RandomNumberGenerator& rng) = delete;
      RandomNumberGenerator& operator=(const RandomNumberGenerator& rng) = delete;

      /**
      * Randomize a byte array.
      * @param output the byte array to hold the random output.
      * @param length the length of the byte array output in bytes.
      */
      virtual void randomize(uint8_t output[], size_t length) = 0;

      /**
      * Returns false if it is known that this RNG object is not able to accept
      * externally provided inputs (via add_entropy, randomize_with_input, etc).
      * In this case, any such provided inputs are ignored.
      *
      * If this function returns true, then inputs may or may not be accepted.
      */
      virtual bool accepts_input() const = 0;

      /**
      * Incorporate some additional data into the RNG state. For
      * example adding nonces or timestamps from a peer's protocol
      * message can help hedge against VM state rollback attacks.
      * A few RNG types do not accept any externally provided input,
      * in which case this function is a no-op.
      *
      * @param input a byte array containg the entropy to be added
      * @param length the length of the byte array in
      */
      virtual void add_entropy(const uint8_t input[], size_t length) = 0;

      /**
      * Incorporate some additional data into the RNG state.
      */
      template<typename T> void add_entropy_T(const T& t)
         {
         static_assert(std::is_standard_layout<T>::value && std::is_trivial<T>::value, "add_entropy_T data must be POD");
         this->add_entropy(reinterpret_cast<const uint8_t*>(&t), sizeof(T));
         }

      /**
      * Incorporate entropy into the RNG state then produce output.
      * Some RNG types implement this using a single operation, default
      * calls add_entropy + randomize in sequence.
      *
      * Use this to further bind the outputs to your current
      * process/protocol state. For instance if generating a new key
      * for use in a session, include a session ID or other such
      * value. See NIST SP 800-90 A, B, C series for more ideas.
      *
      * @param output buffer to hold the random output
      * @param output_len size of the output buffer in bytes
      * @param input entropy buffer to incorporate
      * @param input_len size of the input buffer in bytes
      */
      virtual void randomize_with_input(uint8_t output[], size_t output_len,
                                        const uint8_t input[], size_t input_len);

      /**
      * This calls `randomize_with_input` using some timestamps as extra input.
      *
      * For a stateful RNG using non-random but potentially unique data the
      * extra input can help protect against problems with fork, VM state
      * rollback, or other cases where somehow an RNG state is duplicated. If
      * both of the duplicated RNG states later incorporate a timestamp (and the
      * timestamps don't themselves repeat), their outputs will diverge.
      */
      virtual void randomize_with_ts_input(uint8_t output[], size_t output_len);

      /**
      * @return the name of this RNG type
      */
      virtual std::string name() const = 0;

      /**
      * Clear all internally held values of this RNG
      * @post is_seeded() == false
      */
      virtual void clear() = 0;

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const = 0;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      */
      virtual size_t reseed(Entropy_Sources& srcs,
                            size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                            std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);

      /**
      * Reseed by reading specified bits from the RNG
      */
      virtual void reseed_from_rng(RandomNumberGenerator& rng,
                                   size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS);

      // Some utility functions built on the interface above:

      /**
      * Return a random vector
      * @param bytes number of bytes in the result
      * @return randomized vector of length bytes
      */
      secure_vector<uint8_t> random_vec(size_t bytes)
         {
         secure_vector<uint8_t> output;
         random_vec(output, bytes);
         return output;
         }

      template<typename Alloc>
         void random_vec(std::vector<uint8_t, Alloc>& v, size_t bytes)
         {
         v.resize(bytes);
         this->randomize(v.data(), v.size());
         }

      /**
      * Return a random byte
      * @return random byte
      */
      uint8_t next_byte()
         {
         uint8_t b;
         this->randomize(&b, 1);
         return b;
         }

      /**
      * @return a random byte that is greater than zero
      */
      uint8_t next_nonzero_byte()
         {
         uint8_t b = this->next_byte();
         while(b == 0)
            b = this->next_byte();
         return b;
         }

      /**
      * Create a seeded and active RNG object for general application use
      * Added in 1.8.0
      * Use AutoSeeded_RNG instead
      */
      BOTAN_DEPRECATED("Use AutoSeeded_RNG")
      static RandomNumberGenerator* make_rng();
   };

/**
* Convenience typedef
*/
typedef RandomNumberGenerator RNG;

/**
* Hardware_RNG exists to tag hardware RNG types (PKCS11_RNG, TPM_RNG, Processor_RNG)
*/
class BOTAN_PUBLIC_API(2,0) Hardware_RNG : public RandomNumberGenerator
   {
   public:
      virtual void clear() final override { /* no way to clear state of hardware RNG */ }
   };

/**
* Null/stub RNG - fails if you try to use it for anything
* This is not generally useful except for in certain tests
*/
class BOTAN_PUBLIC_API(2,0) Null_RNG final : public RandomNumberGenerator
   {
   public:
      bool is_seeded() const override { return false; }

      bool accepts_input() const override { return false; }

      void clear() override {}

      void randomize(uint8_t[], size_t) override
         {
         throw PRNG_Unseeded("Null_RNG called");
         }

      void add_entropy(const uint8_t[], size_t) override {}

      std::string name() const override { return "Null_RNG"; }
   };

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
/**
* Wraps access to a RNG in a mutex
* Note that most of the time it's much better to use a RNG per thread
* otherwise the RNG will act as an unnecessary contention point
*
* Since 2.16.0 all Stateful_RNG instances have an internal lock, so
* this class is no longer needed. It will be removed in a future major
* release.
*/
class BOTAN_PUBLIC_API(2,0) Serialized_RNG final : public RandomNumberGenerator
   {
   public:
      void randomize(uint8_t out[], size_t len) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->randomize(out, len);
         }

      bool accepts_input() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->accepts_input();
         }

      bool is_seeded() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->is_seeded();
         }

      void clear() override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->clear();
         }

      std::string name() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->name();
         }

      size_t reseed(Entropy_Sources& src,
                    size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                    std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->reseed(src, poll_bits, poll_timeout);
         }

      void add_entropy(const uint8_t in[], size_t len) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->add_entropy(in, len);
         }

      BOTAN_DEPRECATED("Use Serialized_RNG(new AutoSeeded_RNG) instead") Serialized_RNG();

      /*
      * Since 2.16.0 this is no longer needed for any RNG type. This
      * class will be removed in a future major release.
      */
      explicit Serialized_RNG(RandomNumberGenerator* rng) : m_rng(rng) {}
   private:
      mutable mutex_type m_mutex;
      std::unique_ptr<RandomNumberGenerator> m_rng;
   };
#endif

}

namespace Botan {

class Stateful_RNG;

/**
* A userspace PRNG
*/
class BOTAN_PUBLIC_API(2,0) AutoSeeded_RNG final : public RandomNumberGenerator
   {
   public:
      void randomize(uint8_t out[], size_t len) override;

      void randomize_with_input(uint8_t output[], size_t output_len,
                                const uint8_t input[], size_t input_len) override;

      bool is_seeded() const override;

      bool accepts_input() const override { return true; }

      /**
      * Mark state as requiring a reseed on next use
      */
      void force_reseed();

      size_t reseed(Entropy_Sources& srcs,
                    size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                    std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override;

      void add_entropy(const uint8_t in[], size_t len) override;

      std::string name() const override;

      void clear() override;

      /**
      * Uses the system RNG (if available) or else a default group of
      * entropy sources (all other systems) to gather seed material.
      *
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      AutoSeeded_RNG(size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Create an AutoSeeded_RNG which will get seed material from some other
      * RNG instance. For example you could provide a reference to the system
      * RNG or a hardware RNG.
      *
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      AutoSeeded_RNG(RandomNumberGenerator& underlying_rng,
                     size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Create an AutoSeeded_RNG which will get seed material from a set of
      * entropy sources.
      *
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      AutoSeeded_RNG(Entropy_Sources& entropy_sources,
                     size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      /**
      * Create an AutoSeeded_RNG which will get seed material from both an
      * underlying RNG and a set of entropy sources.
      *
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      AutoSeeded_RNG(RandomNumberGenerator& underlying_rng,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL);

      ~AutoSeeded_RNG();

   private:
      std::unique_ptr<Stateful_RNG> m_rng;
   };

}

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #include <stdlib.h>
#endif

BOTAN_FUTURE_INTERNAL_HEADER(bswap.h)

namespace Botan {

/**
* Swap a 16 bit integer
*/
inline uint16_t reverse_bytes(uint16_t val)
   {
   return static_cast<uint16_t>((val << 8) | (val >> 8));
   }

/**
* Swap a 32 bit integer
*/
inline uint32_t reverse_bytes(uint32_t val)
   {
#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG) || defined(BOTAN_BUILD_COMPILER_IS_XLC)
   return __builtin_bswap32(val);

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   return _byteswap_ulong(val);

#elif defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   // GCC-style inline assembly for x86 or x86-64
   asm("bswapl %0" : "=r" (val) : "0" (val));
   return val;

#else
   // Generic implementation
   uint16_t hi = static_cast<uint16_t>(val >> 16);
   uint16_t lo = static_cast<uint16_t>(val);

   hi = reverse_bytes(hi);
   lo = reverse_bytes(lo);

   return (static_cast<uint32_t>(lo) << 16) | hi;
#endif
   }

/**
* Swap a 64 bit integer
*/
inline uint64_t reverse_bytes(uint64_t val)
   {
#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG) || defined(BOTAN_BUILD_COMPILER_IS_XLC)
   return __builtin_bswap64(val);

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   return _byteswap_uint64(val);

#elif defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_ARCH_IS_X86_64)
   // GCC-style inline assembly for x86-64
   asm("bswapq %0" : "=r" (val) : "0" (val));
   return val;

#else
   /* Generic implementation. Defined in terms of 32-bit bswap so any
    * optimizations in that version can help.
    */

   uint32_t hi = static_cast<uint32_t>(val >> 32);
   uint32_t lo = static_cast<uint32_t>(val);

   hi = reverse_bytes(hi);
   lo = reverse_bytes(lo);

   return (static_cast<uint64_t>(lo) << 32) | hi;
#endif
   }

/**
* Swap 4 Ts in an array
*/
template<typename T>
inline void bswap_4(T x[4])
   {
   x[0] = reverse_bytes(x[0]);
   x[1] = reverse_bytes(x[1]);
   x[2] = reverse_bytes(x[2]);
   x[3] = reverse_bytes(x[3]);
   }

}

namespace Botan {

/**
* This class represents any kind of computation which uses an internal
* state, such as hash functions or MACs
*/
class BOTAN_PUBLIC_API(2,0) Buffered_Computation
   {
   public:
      /**
      * @return length of the output of this function in bytes
      */
      virtual size_t output_length() const = 0;

      /**
      * Add new input to process.
      * @param in the input to process as a byte array
      * @param length of param in in bytes
      */
      void update(const uint8_t in[], size_t length) { add_data(in, length); }

      /**
      * Add new input to process.
      * @param in the input to process as a secure_vector
      */
      void update(const secure_vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         }

      /**
      * Add new input to process.
      * @param in the input to process as a std::vector
      */
      void update(const std::vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         }

      void update_be(uint16_t val);
      void update_be(uint32_t val);
      void update_be(uint64_t val);

      void update_le(uint16_t val);
      void update_le(uint32_t val);
      void update_le(uint64_t val);

      /**
      * Add new input to process.
      * @param str the input to process as a std::string. Will be interpreted
      * as a byte array based on the strings encoding.
      */
      void update(const std::string& str)
         {
         add_data(cast_char_ptr_to_uint8(str.data()), str.size());
         }

      /**
      * Process a single byte.
      * @param in the byte to process
      */
      void update(uint8_t in) { add_data(&in, 1); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @param out The byte array to be filled with the result.
      * Must be of length output_length()
      */
      void final(uint8_t out[]) { final_result(out); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @return secure_vector holding the result
      */
      secure_vector<uint8_t> final()
         {
         secure_vector<uint8_t> output(output_length());
         final_result(output.data());
         return output;
         }

      std::vector<uint8_t> final_stdvec()
         {
         std::vector<uint8_t> output(output_length());
         final_result(output.data());
         return output;
         }

      template<typename Alloc>
         void final(std::vector<uint8_t, Alloc>& out)
         {
         out.resize(output_length());
         final_result(out.data());
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a byte array
      * @param length the length of the byte array
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const uint8_t in[], size_t length)
         {
         add_data(in, length);
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const secure_vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const std::vector<uint8_t>& in)
         {
         add_data(in.data(), in.size());
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a string
      * @result the result of the call to final()
      */
      secure_vector<uint8_t> process(const std::string& in)
         {
         update(in);
         return final();
         }

      virtual ~Buffered_Computation() {}
   private:
      /**
      * Add more data to the computation
      * @param input is an input buffer
      * @param length is the length of input in bytes
      */
      virtual void add_data(const uint8_t input[], size_t length) = 0;

      /**
      * Write the final output to out
      * @param out is an output buffer of output_length()
      */
      virtual void final_result(uint8_t out[]) = 0;
   };

}

namespace Botan {

/**
* Struct representing a particular date and time
*/
class BOTAN_PUBLIC_API(2,0) calendar_point
   {
   public:

      /** The year */
      uint32_t get_year() const { return year; }

      /** The month, 1 through 12 for Jan to Dec */
      uint32_t get_month() const { return month; }

      /** The day of the month, 1 through 31 (or 28 or 30 based on month */
      uint32_t get_day() const { return day; }

      /** Hour in 24-hour form, 0 to 23 */
      uint32_t get_hour() const { return hour; }

      /** Minutes in the hour, 0 to 60 */
      uint32_t get_minutes() const { return minutes; }

      /** Seconds in the minute, 0 to 60, but might be slightly
      larger to deal with leap seconds on some systems
      */
      uint32_t get_seconds() const { return seconds; }

      /**
      * Initialize a calendar_point
      * @param y the year
      * @param mon the month
      * @param d the day
      * @param h the hour
      * @param min the minute
      * @param sec the second
      */
      calendar_point(uint32_t y, uint32_t mon, uint32_t d, uint32_t h, uint32_t min, uint32_t sec) :
         year(y), month(mon), day(d), hour(h), minutes(min), seconds(sec) {}

      /**
      * Returns an STL timepoint object
      */
      std::chrono::system_clock::time_point to_std_timepoint() const;

      /**
      * Returns a human readable string of the struct's components.
      * Formatting might change over time. Currently it is RFC339 'iso-date-time'.
      */
      std::string to_string() const;

   BOTAN_DEPRECATED_PUBLIC_MEMBER_VARIABLES:
      /*
      The member variables are public for historical reasons. Use the get_xxx() functions
      defined above. These members will be made private in a future major release.
      */
      uint32_t year;
      uint32_t month;
      uint32_t day;
      uint32_t hour;
      uint32_t minutes;
      uint32_t seconds;
   };

/**
* Convert a time_point to a calendar_point
* @param time_point a time point from the system clock
* @return calendar_point object representing this time point
*/
BOTAN_PUBLIC_API(2,0) calendar_point calendar_value(
   const std::chrono::system_clock::time_point& time_point);

}

namespace Botan {

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
enum Cipher_Dir : int { ENCRYPTION, DECRYPTION };

/**
* Interface for cipher modes
*/
class BOTAN_PUBLIC_API(2,0) Cipher_Mode : public SymmetricAlgorithm
   {
   public:
      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * Create an AEAD mode
      * @param algo the algorithm to create
      * @param direction specify if this should be an encryption or decryption AEAD
      * @param provider optional specification for provider to use
      * @return an AEAD mode or a null pointer if not available
      */
      static std::unique_ptr<Cipher_Mode> create(const std::string& algo,
                                                 Cipher_Dir direction,
                                                 const std::string& provider = "");

      /**
      * Create an AEAD mode, or throw
      * @param algo the algorithm to create
      * @param direction specify if this should be an encryption or decryption AEAD
      * @param provider optional specification for provider to use
      * @return an AEAD mode, or throw an exception
      */
      static std::unique_ptr<Cipher_Mode> create_or_throw(const std::string& algo,
                                                          Cipher_Dir direction,
                                                          const std::string& provider = "");

      /*
      * Prepare for processing a message under the specified nonce
      */
      virtual void start_msg(const uint8_t nonce[], size_t nonce_len) = 0;

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      void start(const std::vector<uint8_t, Alloc>& nonce)
         {
         start_msg(nonce.data(), nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      void start(const uint8_t nonce[], size_t nonce_len)
         {
         start_msg(nonce, nonce_len);
         }

      /**
      * Begin processing a message.
      */
      void start()
         {
         return start_msg(nullptr, 0);
         }

      /**
      * Process message blocks
      *
      * Input must be a multiple of update_granularity
      *
      * Processes msg in place and returns bytes written. Normally
      * this will be either msg_len (indicating the entire message was
      * processed) or for certain AEAD modes zero (indicating that the
      * mode requires the entire message be processed in one pass).
      *
      * @param msg the message to be processed
      * @param msg_len length of the message in bytes
      */
      virtual size_t process(uint8_t msg[], size_t msg_len) = 0;

      /**
      * Process some data. Input must be in size update_granularity() uint8_t blocks.
      * @param buffer in/out parameter which will possibly be resized
      * @param offset an offset into blocks to begin processing
      */
      void update(secure_vector<uint8_t>& buffer, size_t offset = 0)
         {
         BOTAN_ASSERT(buffer.size() >= offset, "Offset ok");
         uint8_t* buf = buffer.data() + offset;
         const size_t buf_size = buffer.size() - offset;

         const size_t written = process(buf, buf_size);
         buffer.resize(offset + written);
         }

      /**
      * Complete processing of a message.
      *
      * @param final_block in/out parameter which must be at least
      *        minimum_final_size() bytes, and will be set to any final output
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) = 0;

      /**
      * Returns the size of the output if this transform is used to process a
      * message with input_length bytes. In most cases the answer is precise.
      * If it is not possible to precise (namely for CBC decryption) instead a
      * lower bound is returned.
      */
      virtual size_t output_length(size_t input_length) const = 0;

      /**
      * @return size of required blocks to update
      */
      virtual size_t update_granularity() const = 0;

      /**
      * @return required minimium size to finalize() - may be any
      *         length larger than this.
      */
      virtual size_t minimum_final_size() const = 0;

      /**
      * @return the default size for a nonce
      */
      virtual size_t default_nonce_length() const = 0;

      /**
      * @return true iff nonce_len is a valid length for the nonce
      */
      virtual bool valid_nonce_length(size_t nonce_len) const = 0;

      /**
      * Resets just the message specific state and allows encrypting again under the existing key
      */
      virtual void reset() = 0;

      /**
      * @return true iff this mode provides authentication as well as
      * confidentiality.
      */
      virtual bool authenticated() const { return false; }

      /**
      * @return the size of the authentication tag used (in bytes)
      */
      virtual size_t tag_size() const { return 0; }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }
   };

/**
* Get a cipher mode by name (eg "AES-128/CBC" or "Serpent/XTS")
* @param algo_spec cipher name
* @param direction ENCRYPTION or DECRYPTION
* @param provider provider implementation to choose
*/
inline Cipher_Mode* get_cipher_mode(const std::string& algo_spec,
                                    Cipher_Dir direction,
                                    const std::string& provider = "")
   {
   return Cipher_Mode::create(algo_spec, direction, provider).release();
   }

}

BOTAN_FUTURE_INTERNAL_HEADER(mode_pad.h)

namespace Botan {

/**
* Block Cipher Mode Padding Method
* This class is pretty limited, it cannot deal well with
* randomized padding methods, or any padding method that
* wants to add more than one block. For instance, it should
* be possible to define cipher text stealing mode as simply
* a padding mode for CBC, which happens to consume the last
* two block (and requires use of the block cipher).
*/
class BOTAN_PUBLIC_API(2,0) BlockCipherModePaddingMethod
   {
   public:
      /**
      * Add padding bytes to buffer.
      * @param buffer data to pad
      * @param final_block_bytes size of the final block in bytes
      * @param block_size size of each block in bytes
      */
      virtual void add_padding(secure_vector<uint8_t>& buffer,
                               size_t final_block_bytes,
                               size_t block_size) const = 0;

      /**
      * Remove padding bytes from block
      * @param block the last block
      * @param len the size of the block in bytes
      * @return number of data bytes, or if the padding is invalid returns len
      */
      virtual size_t unpad(const uint8_t block[], size_t len) const = 0;

      /**
      * @param block_size of the cipher
      * @return valid block size for this padding mode
      */
      virtual bool valid_blocksize(size_t block_size) const = 0;

      /**
      * @return name of the mode
      */
      virtual std::string name() const = 0;

      /**
      * virtual destructor
      */
      virtual ~BlockCipherModePaddingMethod() {}
   };

/**
* PKCS#7 Padding
*/
class BOTAN_PUBLIC_API(2,0) PKCS7_Padding final : public BlockCipherModePaddingMethod
   {
   public:
      void add_padding(secure_vector<uint8_t>& buffer,
                       size_t final_block_bytes,
                       size_t block_size) const override;

      size_t unpad(const uint8_t[], size_t) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2 && bs < 256); }

      std::string name() const override { return "PKCS7"; }
   };

/**
* ANSI X9.23 Padding
*/
class BOTAN_PUBLIC_API(2,0) ANSI_X923_Padding final : public BlockCipherModePaddingMethod
   {
   public:
      void add_padding(secure_vector<uint8_t>& buffer,
                       size_t final_block_bytes,
                       size_t block_size) const override;

      size_t unpad(const uint8_t[], size_t) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2 && bs < 256); }

      std::string name() const override { return "X9.23"; }
   };

/**
* One And Zeros Padding (ISO/IEC 9797-1, padding method 2)
*/
class BOTAN_PUBLIC_API(2,0) OneAndZeros_Padding final : public BlockCipherModePaddingMethod
   {
   public:
      void add_padding(secure_vector<uint8_t>& buffer,
                       size_t final_block_bytes,
                       size_t block_size) const override;

      size_t unpad(const uint8_t[], size_t) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2); }

      std::string name() const override { return "OneAndZeros"; }
   };

/**
* ESP Padding (RFC 4304)
*/
class BOTAN_PUBLIC_API(2,0) ESP_Padding final : public BlockCipherModePaddingMethod
   {
   public:
      void add_padding(secure_vector<uint8_t>& buffer,
                       size_t final_block_bytes,
                       size_t block_size) const override;

      size_t unpad(const uint8_t[], size_t) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2 && bs < 256); }

      std::string name() const override { return "ESP"; }
   };

/**
* Null Padding
*/
class BOTAN_PUBLIC_API(2,0) Null_Padding final : public BlockCipherModePaddingMethod
   {
   public:
      void add_padding(secure_vector<uint8_t>&, size_t, size_t) const override
         {
         /* no padding */
         }

      size_t unpad(const uint8_t[], size_t size) const override { return size; }

      bool valid_blocksize(size_t) const override { return true; }

      std::string name() const override { return "NoPadding"; }
   };

/**
* Get a block cipher padding mode by name (eg "NoPadding" or "PKCS7")
* @param algo_spec block cipher padding mode name
*/
BOTAN_PUBLIC_API(2,0) BlockCipherModePaddingMethod* get_bc_pad(const std::string& algo_spec);

}

BOTAN_FUTURE_INTERNAL_HEADER(cbc.h)

namespace Botan {

/**
* CBC Mode
*/
class BOTAN_PUBLIC_API(2,0) CBC_Mode : public Cipher_Mode
   {
   public:
      std::string name() const override;

      size_t update_granularity() const override;

      Key_Length_Specification key_spec() const override;

      size_t default_nonce_length() const override;

      bool valid_nonce_length(size_t n) const override;

      void clear() override;

      void reset() override;

   protected:
      CBC_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding);

      const BlockCipher& cipher() const { return *m_cipher; }

      const BlockCipherModePaddingMethod& padding() const
         {
         BOTAN_ASSERT_NONNULL(m_padding);
         return *m_padding;
         }

      size_t block_size() const { return m_block_size; }

      secure_vector<uint8_t>& state() { return m_state; }

      uint8_t* state_ptr() { return m_state.data(); }

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override;

      void key_schedule(const uint8_t key[], size_t length) override;

      std::unique_ptr<BlockCipher> m_cipher;
      std::unique_ptr<BlockCipherModePaddingMethod> m_padding;
      secure_vector<uint8_t> m_state;
      size_t m_block_size;
   };

/**
* CBC Encryption
*/
class BOTAN_PUBLIC_API(2,0) CBC_Encryption : public CBC_Mode
   {
   public:
      /**
      * @param cipher block cipher to use
      * @param padding padding method to use
      */
      CBC_Encryption(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
         CBC_Mode(cipher, padding) {}

      size_t process(uint8_t buf[], size_t size) override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;
   };

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
class BOTAN_PUBLIC_API(2,0) CTS_Encryption final : public CBC_Encryption
   {
   public:
      /**
      * @param cipher block cipher to use
      */
      explicit CTS_Encryption(BlockCipher* cipher) : CBC_Encryption(cipher, nullptr) {}

      size_t output_length(size_t input_length) const override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      size_t minimum_final_size() const override;

      bool valid_nonce_length(size_t n) const override;
   };

/**
* CBC Decryption
*/
class BOTAN_PUBLIC_API(2,0) CBC_Decryption : public CBC_Mode
   {
   public:
      /**
      * @param cipher block cipher to use
      * @param padding padding method to use
      */
      CBC_Decryption(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
         CBC_Mode(cipher, padding), m_tempbuf(update_granularity()) {}

      size_t process(uint8_t buf[], size_t size) override;

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      size_t output_length(size_t input_length) const override;

      size_t minimum_final_size() const override;

      void reset() override;

   private:
      secure_vector<uint8_t> m_tempbuf;
   };

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
class BOTAN_PUBLIC_API(2,0) CTS_Decryption final : public CBC_Decryption
   {
   public:
      /**
      * @param cipher block cipher to use
      */
      explicit CTS_Decryption(BlockCipher* cipher) : CBC_Decryption(cipher, nullptr) {}

      void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) override;

      size_t minimum_final_size() const override;

      bool valid_nonce_length(size_t n) const override;
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(charset.h)

namespace Botan {

/**
* Convert a sequence of UCS-2 (big endian) characters to a UTF-8 string
* This is used for ASN.1 BMPString type
* @param ucs2 the sequence of UCS-2 characters
* @param len length of ucs2 in bytes, must be a multiple of 2
*/
std::string BOTAN_UNSTABLE_API ucs2_to_utf8(const uint8_t ucs2[], size_t len);

/**
* Convert a sequence of UCS-4 (big endian) characters to a UTF-8 string
* This is used for ASN.1 UniversalString type
* @param ucs4 the sequence of UCS-4 characters
* @param len length of ucs4 in bytes, must be a multiple of 4
*/
std::string BOTAN_UNSTABLE_API ucs4_to_utf8(const uint8_t ucs4[], size_t len);

/**
* Convert a UTF-8 string to Latin-1
* If a character outside the Latin-1 range is encountered, an exception is thrown.
*/
std::string BOTAN_UNSTABLE_API utf8_to_latin1(const std::string& utf8);

/**
* The different charsets (nominally) supported by Botan.
*/
enum Character_Set {
   LOCAL_CHARSET,
   UCS2_CHARSET,
   UTF8_CHARSET,
   LATIN1_CHARSET
};

namespace Charset {

/*
* Character set conversion - avoid this.
* For specific conversions, use the functions above like
* ucs2_to_utf8 and utf8_to_latin1
*
* If you need something more complex than that, use a real library
* such as iconv, Boost.Locale, or ICU
*/
std::string BOTAN_PUBLIC_API(2,0)
   BOTAN_DEPRECATED("Avoid. See comment in header.")
   transcode(const std::string& str,
             Character_Set to,
             Character_Set from);

/*
* Simple character classifier functions
*/
bool BOTAN_PUBLIC_API(2,0) is_digit(char c);
bool BOTAN_PUBLIC_API(2,0) is_space(char c);
bool BOTAN_PUBLIC_API(2,0) caseless_cmp(char x, char y);

uint8_t BOTAN_PUBLIC_API(2,0) char2digit(char c);
char BOTAN_PUBLIC_API(2,0) digit2char(uint8_t b);

}

}

BOTAN_FUTURE_INTERNAL_HEADER(cpuid.h)

namespace Botan {

/**
* A class handling runtime CPU feature detection. It is limited to
* just the features necessary to implement CPU specific code in Botan,
* rather than being a general purpose utility.
*
* This class supports:
*
*  - x86 features using CPUID. x86 is also the only processor with
*    accurate cache line detection currently.
*
*  - PowerPC AltiVec detection on Linux, NetBSD, OpenBSD, and macOS
*
*  - ARM NEON and crypto extensions detection. On Linux and Android
*    systems which support getauxval, that is used to access CPU
*    feature information. Otherwise a relatively portable but
*    thread-unsafe mechanism involving executing probe functions which
*    catching SIGILL signal is used.
*/
class BOTAN_PUBLIC_API(2,1) CPUID final
   {
   public:
      /**
      * Probe the CPU and see what extensions are supported
      */
      static void initialize();

      static bool has_simd_32();

      /**
      * Deprecated equivalent to
      * o << "CPUID flags: " << CPUID::to_string() << "\n";
      */
      BOTAN_DEPRECATED("Use CPUID::to_string")
      static void print(std::ostream& o);

      /**
      * Return a possibly empty string containing list of known CPU
      * extensions. Each name will be seperated by a space, and the ordering
      * will be arbitrary. This list only contains values that are useful to
      * Botan (for example FMA instructions are not checked).
      *
      * Example outputs "sse2 ssse3 rdtsc", "neon arm_aes", "altivec"
      */
      static std::string to_string();

      /**
      * Return a best guess of the cache line size
      */
      static size_t cache_line_size()
         {
         return state().cache_line_size();
         }

      static bool is_little_endian()
         {
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
         return true;
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
         return false;
#else
         return state().endian_status() == Endian_Status::Little;
#endif
         }

      static bool is_big_endian()
         {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
         return true;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
         return false;
#else
         return state().endian_status() == Endian_Status::Big;
#endif
         }

      enum CPUID_bits : uint64_t {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         // These values have no relation to cpuid bitfields

         // SIMD instruction sets
         CPUID_SSE2_BIT       = (1ULL << 0),
         CPUID_SSSE3_BIT      = (1ULL << 1),
         CPUID_SSE41_BIT      = (1ULL << 2),
         CPUID_SSE42_BIT      = (1ULL << 3),
         CPUID_AVX2_BIT       = (1ULL << 4),
         CPUID_AVX512F_BIT    = (1ULL << 5),

         CPUID_AVX512DQ_BIT   = (1ULL << 6),
         CPUID_AVX512BW_BIT   = (1ULL << 7),

         // Ice Lake profile: AVX-512 F, DQ, BW, IFMA, VBMI, VBMI2, BITALG
         CPUID_AVX512_ICL_BIT = (1ULL << 11),

         // Crypto-specific ISAs
         CPUID_AESNI_BIT        = (1ULL << 16),
         CPUID_CLMUL_BIT        = (1ULL << 17),
         CPUID_RDRAND_BIT       = (1ULL << 18),
         CPUID_RDSEED_BIT       = (1ULL << 19),
         CPUID_SHA_BIT          = (1ULL << 20),
         CPUID_AVX512_AES_BIT   = (1ULL << 21),
         CPUID_AVX512_CLMUL_BIT = (1ULL << 22),

         // Misc useful instructions
         CPUID_RDTSC_BIT      = (1ULL << 48),
         CPUID_ADX_BIT        = (1ULL << 49),
         CPUID_BMI1_BIT       = (1ULL << 50),
         CPUID_BMI2_BIT       = (1ULL << 51),
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         CPUID_ALTIVEC_BIT    = (1ULL << 0),
         CPUID_POWER_CRYPTO_BIT = (1ULL << 1),
         CPUID_DARN_BIT       = (1ULL << 2),
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         CPUID_ARM_NEON_BIT      = (1ULL << 0),
         CPUID_ARM_SVE_BIT       = (1ULL << 1),
         CPUID_ARM_AES_BIT       = (1ULL << 16),
         CPUID_ARM_PMULL_BIT     = (1ULL << 17),
         CPUID_ARM_SHA1_BIT      = (1ULL << 18),
         CPUID_ARM_SHA2_BIT      = (1ULL << 19),
         CPUID_ARM_SHA3_BIT      = (1ULL << 20),
         CPUID_ARM_SHA2_512_BIT  = (1ULL << 21),
         CPUID_ARM_SM3_BIT       = (1ULL << 22),
         CPUID_ARM_SM4_BIT       = (1ULL << 23),
#endif

         CPUID_INITIALIZED_BIT = (1ULL << 63)
      };

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
      /**
      * Check if the processor supports AltiVec/VMX
      */
      static bool has_altivec()
         { return has_cpuid_bit(CPUID_ALTIVEC_BIT); }

      /**
      * Check if the processor supports POWER8 crypto extensions
      */
      static bool has_power_crypto()
         { return has_cpuid_bit(CPUID_POWER_CRYPTO_BIT); }

      /**
      * Check if the processor supports POWER9 DARN RNG
      */
      static bool has_darn_rng()
         { return has_cpuid_bit(CPUID_DARN_BIT); }

#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
      /**
      * Check if the processor supports NEON SIMD
      */
      static bool has_neon()
         { return has_cpuid_bit(CPUID_ARM_NEON_BIT); }

      /**
      * Check if the processor supports ARMv8 SVE
      */
      static bool has_arm_sve()
         { return has_cpuid_bit(CPUID_ARM_SVE_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA1
      */
      static bool has_arm_sha1()
         { return has_cpuid_bit(CPUID_ARM_SHA1_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA2
      */
      static bool has_arm_sha2()
         { return has_cpuid_bit(CPUID_ARM_SHA2_BIT); }

      /**
      * Check if the processor supports ARMv8 AES
      */
      static bool has_arm_aes()
         { return has_cpuid_bit(CPUID_ARM_AES_BIT); }

      /**
      * Check if the processor supports ARMv8 PMULL
      */
      static bool has_arm_pmull()
         { return has_cpuid_bit(CPUID_ARM_PMULL_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA-512
      */
      static bool has_arm_sha2_512()
         { return has_cpuid_bit(CPUID_ARM_SHA2_512_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA-3
      */
      static bool has_arm_sha3()
         { return has_cpuid_bit(CPUID_ARM_SHA3_BIT); }

      /**
      * Check if the processor supports ARMv8 SM3
      */
      static bool has_arm_sm3()
         { return has_cpuid_bit(CPUID_ARM_SM3_BIT); }

      /**
      * Check if the processor supports ARMv8 SM4
      */
      static bool has_arm_sm4()
         { return has_cpuid_bit(CPUID_ARM_SM4_BIT); }

#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

      /**
      * Check if the processor supports RDTSC
      */
      static bool has_rdtsc()
         { return has_cpuid_bit(CPUID_RDTSC_BIT); }

      /**
      * Check if the processor supports SSE2
      */
      static bool has_sse2()
         { return has_cpuid_bit(CPUID_SSE2_BIT); }

      /**
      * Check if the processor supports SSSE3
      */
      static bool has_ssse3()
         { return has_cpuid_bit(CPUID_SSSE3_BIT); }

      /**
      * Check if the processor supports SSE4.1
      */
      static bool has_sse41()
         { return has_cpuid_bit(CPUID_SSE41_BIT); }

      /**
      * Check if the processor supports SSE4.2
      */
      static bool has_sse42()
         { return has_cpuid_bit(CPUID_SSE42_BIT); }

      /**
      * Check if the processor supports AVX2
      */
      static bool has_avx2()
         { return has_cpuid_bit(CPUID_AVX2_BIT); }

      /**
      * Check if the processor supports AVX-512F
      */
      static bool has_avx512f()
         { return has_cpuid_bit(CPUID_AVX512F_BIT); }

      /**
      * Check if the processor supports AVX-512DQ
      */
      static bool has_avx512dq()
         { return has_cpuid_bit(CPUID_AVX512DQ_BIT); }

      /**
      * Check if the processor supports AVX-512BW
      */
      static bool has_avx512bw()
         { return has_cpuid_bit(CPUID_AVX512BW_BIT); }

      /**
      * Check if the processor supports AVX-512 Ice Lake profile
      */
      static bool has_avx512_icelake()
         { return has_cpuid_bit(CPUID_AVX512_ICL_BIT); }

      /**
      * Check if the processor supports AVX-512 AES (VAES)
      */
      static bool has_avx512_aes()
         { return has_cpuid_bit(CPUID_AVX512_AES_BIT); }

      /**
      * Check if the processor supports AVX-512 VPCLMULQDQ
      */
      static bool has_avx512_clmul()
         { return has_cpuid_bit(CPUID_AVX512_CLMUL_BIT); }

      /**
      * Check if the processor supports BMI1
      */
      static bool has_bmi1()
         { return has_cpuid_bit(CPUID_BMI1_BIT); }

      /**
      * Check if the processor supports BMI2
      */
      static bool has_bmi2()
         { return has_cpuid_bit(CPUID_BMI2_BIT); }

      /**
      * Check if the processor supports AES-NI
      */
      static bool has_aes_ni()
         { return has_cpuid_bit(CPUID_AESNI_BIT); }

      /**
      * Check if the processor supports CLMUL
      */
      static bool has_clmul()
         { return has_cpuid_bit(CPUID_CLMUL_BIT); }

      /**
      * Check if the processor supports Intel SHA extension
      */
      static bool has_intel_sha()
         { return has_cpuid_bit(CPUID_SHA_BIT); }

      /**
      * Check if the processor supports ADX extension
      */
      static bool has_adx()
         { return has_cpuid_bit(CPUID_ADX_BIT); }

      /**
      * Check if the processor supports RDRAND
      */
      static bool has_rdrand()
         { return has_cpuid_bit(CPUID_RDRAND_BIT); }

      /**
      * Check if the processor supports RDSEED
      */
      static bool has_rdseed()
         { return has_cpuid_bit(CPUID_RDSEED_BIT); }
#endif

      /**
      * Check if the processor supports byte-level vector permutes
      * (SSSE3, NEON, Altivec)
      */
      static bool has_vperm()
         {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_ssse3();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_neon();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         return has_altivec();
#else
         return false;
#endif
         }

      /**
      * Check if the processor supports hardware AES instructions
      */
      static bool has_hw_aes()
         {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_aes_ni();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_arm_aes();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         return has_power_crypto();
#else
         return false;
#endif
         }

      /**
      * Check if the processor supports carryless multiply
      * (CLMUL, PMULL)
      */
      static bool has_carryless_multiply()
         {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_clmul();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_arm_pmull();
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
         return has_power_crypto();
#else
         return false;
#endif
         }

      /*
      * Clear a CPUID bit
      * Call CPUID::initialize to reset
      *
      * This is only exposed for testing, don't use unless you know
      * what you are doing.
      */
      static void clear_cpuid_bit(CPUID_bits bit)
         {
         state().clear_cpuid_bit(static_cast<uint64_t>(bit));
         }

      /*
      * Don't call this function, use CPUID::has_xxx above
      * It is only exposed for the tests.
      */
      static bool has_cpuid_bit(CPUID_bits elem)
         {
         const uint64_t elem64 = static_cast<uint64_t>(elem);
         return state().has_bit(elem64);
         }

      static std::vector<CPUID::CPUID_bits> bit_from_string(const std::string& tok);
   private:
      enum class Endian_Status : uint32_t {
         Unknown = 0x00000000,
         Big     = 0x01234567,
         Little  = 0x67452301,
      };

      struct CPUID_Data
         {
         public:
            CPUID_Data();

            CPUID_Data(const CPUID_Data& other) = default;
            CPUID_Data& operator=(const CPUID_Data& other) = default;

            void clear_cpuid_bit(uint64_t bit)
               {
               m_processor_features &= ~bit;
               }

            bool has_bit(uint64_t bit) const
               {
               return (m_processor_features & bit) == bit;
               }

            uint64_t processor_features() const { return m_processor_features; }
            Endian_Status endian_status() const { return m_endian_status; }
            size_t cache_line_size() const { return m_cache_line_size; }

         private:
            static Endian_Status runtime_check_endian();

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

            static uint64_t detect_cpu_features(size_t* cache_line_size);

#endif
            uint64_t m_processor_features;
            size_t m_cache_line_size;
            Endian_Status m_endian_status;
         };

      static CPUID_Data& state()
         {
         static CPUID::CPUID_Data g_cpuid;
         return g_cpuid;
         }
   };

}

namespace Botan {

/**
* This class represents an abstract data source object.
*/
class BOTAN_PUBLIC_API(2,0) DataSource
   {
   public:
      /**
      * Read from the source. Moves the internal offset so that every
      * call to read will return a new portion of the source.
      *
      * @param out the byte array to write the result to
      * @param length the length of the byte array out
      * @return length in bytes that was actually read and put
      * into out
      */
      virtual size_t read(uint8_t out[], size_t length) BOTAN_WARN_UNUSED_RESULT = 0;

      virtual bool check_available(size_t n) = 0;

      /**
      * Read from the source but do not modify the internal
      * offset. Consecutive calls to peek() will return portions of
      * the source starting at the same position.
      *
      * @param out the byte array to write the output to
      * @param length the length of the byte array out
      * @param peek_offset the offset into the stream to read at
      * @return length in bytes that was actually read and put
      * into out
      */
      virtual size_t peek(uint8_t out[], size_t length, size_t peek_offset) const BOTAN_WARN_UNUSED_RESULT = 0;

      /**
      * Test whether the source still has data that can be read.
      * @return true if there is no more data to read, false otherwise
      */
      virtual bool end_of_data() const = 0;
      /**
      * return the id of this data source
      * @return std::string representing the id of this data source
      */
      virtual std::string id() const { return ""; }

      /**
      * Read one byte.
      * @param out the byte to read to
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t read_byte(uint8_t& out);

      /**
      * Peek at one byte.
      * @param out an output byte
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t peek_byte(uint8_t& out) const;

      /**
      * Discard the next N bytes of the data
      * @param N the number of bytes to discard
      * @return number of bytes actually discarded
      */
      size_t discard_next(size_t N);

      /**
      * @return number of bytes read so far.
      */
      virtual size_t get_bytes_read() const = 0;

      DataSource() = default;
      virtual ~DataSource() {}
      DataSource& operator=(const DataSource&) = delete;
      DataSource(const DataSource&) = delete;
   };

/**
* This class represents a Memory-Based DataSource
*/
class BOTAN_PUBLIC_API(2,0) DataSource_Memory final : public DataSource
   {
   public:
      size_t read(uint8_t[], size_t) override;
      size_t peek(uint8_t[], size_t, size_t) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;

      /**
      * Construct a memory source that reads from a string
      * @param in the string to read from
      */
      explicit DataSource_Memory(const std::string& in);

      /**
      * Construct a memory source that reads from a byte array
      * @param in the byte array to read from
      * @param length the length of the byte array
      */
      DataSource_Memory(const uint8_t in[], size_t length) :
         m_source(in, in + length), m_offset(0) {}

      /**
      * Construct a memory source that reads from a secure_vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(const secure_vector<uint8_t>& in) :
         m_source(in), m_offset(0) {}

      /**
      * Construct a memory source that reads from a std::vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(const std::vector<uint8_t>& in) :
         m_source(in.begin(), in.end()), m_offset(0) {}

      size_t get_bytes_read() const override { return m_offset; }
   private:
      secure_vector<uint8_t> m_source;
      size_t m_offset;
   };

/**
* This class represents a Stream-Based DataSource.
*/
class BOTAN_PUBLIC_API(2,0) DataSource_Stream final : public DataSource
   {
   public:
      size_t read(uint8_t[], size_t) override;
      size_t peek(uint8_t[], size_t, size_t) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;
      std::string id() const override;

      DataSource_Stream(std::istream&,
                        const std::string& id = "<std::istream>");

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Construct a Stream-Based DataSource from filesystem path
      * @param file the path to the file
      * @param use_binary whether to treat the file as binary or not
      */
      DataSource_Stream(const std::string& file, bool use_binary = false);
#endif

      DataSource_Stream(const DataSource_Stream&) = delete;

      DataSource_Stream& operator=(const DataSource_Stream&) = delete;

      ~DataSource_Stream();

      size_t get_bytes_read() const override { return m_total_read; }
   private:
      const std::string m_identifier;

      std::unique_ptr<std::istream> m_source_memory;
      std::istream& m_source;
      size_t m_total_read;
   };

}

namespace Botan {

class BOTAN_PUBLIC_API(2,0) SQL_Database
   {
   public:

      class BOTAN_PUBLIC_API(2,0) SQL_DB_Error final : public Exception
         {
         public:
            explicit SQL_DB_Error(const std::string& what) :
               Exception("SQL database", what),
               m_rc(0)
               {}

            SQL_DB_Error(const std::string& what, int rc) :
               Exception("SQL database", what),
               m_rc(rc)
               {}

            ErrorType error_type() const noexcept override { return Botan::ErrorType::DatabaseError; }

            int error_code() const noexcept override { return m_rc; }
         private:
            int m_rc;
         };

      class BOTAN_PUBLIC_API(2,0) Statement
         {
         public:
            /* Bind statement parameters */
            virtual void bind(int column, const std::string& str) = 0;

            virtual void bind(int column, size_t i) = 0;

            virtual void bind(int column, std::chrono::system_clock::time_point time) = 0;

            virtual void bind(int column, const std::vector<uint8_t>& blob) = 0;

            virtual void bind(int column, const uint8_t* data, size_t len) = 0;

            /* Get output */
            virtual std::pair<const uint8_t*, size_t> get_blob(int column) = 0;

            virtual std::string get_str(int column) = 0;

            virtual size_t get_size_t(int column) = 0;

            /* Run to completion */
            virtual size_t spin() = 0;

            /* Maybe update */
            virtual bool step() = 0;

            virtual ~Statement() {}
         };

      /*
      * Create a new statement for execution.
      * Use ?1, ?2, ?3, etc for parameters to set later with bind
      */
      virtual std::shared_ptr<Statement> new_statement(const std::string& base_sql) const = 0;

      virtual size_t row_count(const std::string& table_name) = 0;

      virtual void create_table(const std::string& table_schema) = 0;

      virtual ~SQL_Database() {}
};

}

namespace Botan {

class RandomNumberGenerator;

/**
* Abstract interface to a source of entropy
*/
class BOTAN_PUBLIC_API(2,0) Entropy_Source
   {
   public:
      /**
      * Return a new entropy source of a particular type, or null
      * Each entropy source may require substantial resources (eg, a file handle
      * or socket instance), so try to share them among multiple RNGs, or just
      * use the preconfigured global list accessed by Entropy_Sources::global_sources()
      */
      static std::unique_ptr<Entropy_Source> create(const std::string& type);

      /**
      * @return name identifying this entropy source
      */
      virtual std::string name() const = 0;

      /**
      * Perform an entropy gathering poll
      * @param rng will be provided with entropy via calls to add_entropy
      * @return conservative estimate of actual entropy added to rng during poll
      */
      virtual size_t poll(RandomNumberGenerator& rng) = 0;

      Entropy_Source() = default;
      Entropy_Source(const Entropy_Source& other) = delete;
      Entropy_Source(Entropy_Source&& other) = delete;
      Entropy_Source& operator=(const Entropy_Source& other) = delete;

      virtual ~Entropy_Source() {}
   };

class BOTAN_PUBLIC_API(2,0) Entropy_Sources final
   {
   public:
      static Entropy_Sources& global_sources();

      void add_source(std::unique_ptr<Entropy_Source> src);

      std::vector<std::string> enabled_sources() const;

      size_t poll(RandomNumberGenerator& rng,
                  size_t bits,
                  std::chrono::milliseconds timeout);

      /**
      * Poll just a single named source. Ordinally only used for testing
      */
      size_t poll_just(RandomNumberGenerator& rng, const std::string& src);

      Entropy_Sources() = default;
      explicit Entropy_Sources(const std::vector<std::string>& sources);

      Entropy_Sources(const Entropy_Sources& other) = delete;
      Entropy_Sources(Entropy_Sources&& other) = delete;
      Entropy_Sources& operator=(const Entropy_Sources& other) = delete;

   private:
      std::vector<std::unique_ptr<Entropy_Source>> m_srcs;
   };

}

namespace Botan {

/**
* This class represents hash function (message digest) objects
*/
class BOTAN_PUBLIC_API(2,0) HashFunction : public Buffered_Computation
   {
   public:
      /**
      * Create an instance based on a name, or return null if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<HashFunction>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * Throws Lookup_Error if not found.
      */
      static std::unique_ptr<HashFunction>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual HashFunction* clone() const = 0;

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      virtual ~HashFunction() {}

      /**
      * Reset the state.
      */
      virtual void clear() = 0;

      /**
      * @return the hash function name
      */
      virtual std::string name() const = 0;

      /**
      * @return hash block size as defined for this algorithm
      */
      virtual size_t hash_block_size() const { return 0; }

      /**
      * Return a new hash object with the same state as *this. This
      * allows computing the hash of several messages with a common
      * prefix more efficiently than would otherwise be possible.
      *
      * This function should be called `clone` but that was already
      * used for the case of returning an uninitialized object.
      * @return new hash object
      */
      virtual std::unique_ptr<HashFunction> copy_state() const = 0;
   };

}

namespace Botan {

/**
* Perform hex encoding
* @param output an array of at least input_length*2 bytes
* @param input is some binary data
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
*/
void BOTAN_PUBLIC_API(2,0) hex_encode(char output[],
                          const uint8_t input[],
                          size_t input_length,
                          bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param input_length length of input in bytes
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
std::string BOTAN_PUBLIC_API(2,0) hex_encode(const uint8_t input[],
                                 size_t input_length,
                                 bool uppercase = true);

/**
* Perform hex encoding
* @param input some input
* @param uppercase should output be upper or lower case?
* @return hexadecimal representation of input
*/
template<typename Alloc>
std::string hex_encode(const std::vector<uint8_t, Alloc>& input,
                       bool uppercase = true)
   {
   return hex_encode(input.data(), input.size(), uppercase);
   }

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param input_consumed is an output parameter which says how many
*        bytes of input were actually consumed. If less than
*        input_length, then the range input[consumed:length]
*        should be passed in later along with more input.
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) hex_decode(uint8_t output[],
                            const char input[],
                            size_t input_length,
                            size_t& input_consumed,
                            bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param input_length length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) hex_decode(uint8_t output[],
                            const char input[],
                            size_t input_length,
                            bool ignore_ws = true);

/**
* Perform hex decoding
* @param output an array of at least input_length/2 bytes
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return number of bytes written to output
*/
size_t BOTAN_PUBLIC_API(2,0) hex_decode(uint8_t output[],
                            const std::string& input,
                            bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode(const char input[],
           size_t input_length,
           bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
std::vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode(const std::string& input,
           bool ignore_ws = true);


/**
* Perform hex decoding
* @param input some hex input
* @param input_length the length of input in bytes
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode_locked(const char input[],
                  size_t input_length,
                  bool ignore_ws = true);

/**
* Perform hex decoding
* @param input some hex input
* @param ignore_ws ignore whitespace on input; if false, throw an
                   exception if whitespace is encountered
* @return decoded hex output
*/
secure_vector<uint8_t> BOTAN_PUBLIC_API(2,0)
hex_decode_locked(const std::string& input,
                  bool ignore_ws = true);

}

namespace Botan {

/**
* This class represents Message Authentication Code (MAC) objects.
*/
class BOTAN_PUBLIC_API(2,0) MessageAuthenticationCode : public Buffered_Computation,
                                            public SymmetricAlgorithm
   {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<MessageAuthenticationCode>
         create(const std::string& algo_spec,
                const std::string& provider = "");

      /*
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to use
      * Throws a Lookup_Error if algo/provider combination cannot be found
      */
      static std::unique_ptr<MessageAuthenticationCode>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      virtual ~MessageAuthenticationCode() {}

      /**
      * Prepare for processing a message under the specified nonce
      *
      * Most MACs neither require nor support a nonce; for these algorithms
      * calling `start_msg` is optional and calling it with anything other than
      * an empty string is an error. One MAC which *requires* a per-message
      * nonce be specified is GMAC.
      *
      * @param nonce the message nonce bytes
      * @param nonce_len the size of len in bytes
      * Default implementation simply rejects all non-empty nonces
      * since most hash/MAC algorithms do not support randomization
      */
      virtual void start_msg(const uint8_t nonce[], size_t nonce_len);

      /**
      * Begin processing a message with a nonce
      *
      * @param nonce the per message nonce
      */
      template<typename Alloc>
      void start(const std::vector<uint8_t, Alloc>& nonce)
         {
         start_msg(nonce.data(), nonce.size());
         }

      /**
      * Begin processing a message.
      * @param nonce the per message nonce
      * @param nonce_len length of nonce
      */
      void start(const uint8_t nonce[], size_t nonce_len)
         {
         start_msg(nonce, nonce_len);
         }

      /**
      * Begin processing a message.
      */
      void start()
         {
         return start_msg(nullptr, 0);
         }

      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @param length the length of param in
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const uint8_t in[], size_t length);

      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const std::vector<uint8_t>& in)
         {
         return verify_mac(in.data(), in.size());
         }

      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const secure_vector<uint8_t>& in)
         {
         return verify_mac(in.data(), in.size());
         }

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual MessageAuthenticationCode* clone() const = 0;

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

   };

typedef MessageAuthenticationCode MAC;

}

BOTAN_FUTURE_INTERNAL_HEADER(hmac.h)

namespace Botan {

/**
* HMAC
*/
class BOTAN_PUBLIC_API(2,0) HMAC final : public MessageAuthenticationCode
   {
   public:
      void clear() override;
      std::string name() const override;
      MessageAuthenticationCode* clone() const override;

      size_t output_length() const override;

      Key_Length_Specification key_spec() const override;

      /**
      * @param hash the hash to use for HMACing
      */
      explicit HMAC(HashFunction* hash);

      HMAC(const HMAC&) = delete;
      HMAC& operator=(const HMAC&) = delete;
   private:
      void add_data(const uint8_t[], size_t) override;
      void final_result(uint8_t[]) override;
      void key_schedule(const uint8_t[], size_t) override;

      std::unique_ptr<HashFunction> m_hash;
      secure_vector<uint8_t> m_ikey, m_okey;
      size_t m_hash_output_length;
      size_t m_hash_block_size;
   };

}

namespace Botan {

/**
* Inherited by RNGs which maintain in-process state, like HMAC_DRBG.
* On Unix these RNGs are vulnerable to problems with fork, where the
* RNG state is duplicated, and the parent and child process RNGs will
* produce identical output until one of them reseeds. Stateful_RNG
* reseeds itself whenever a fork is detected, or after a set number of
* bytes have been output.
*
* Not implemented by RNGs which access an external RNG, such as the
* system PRNG or a hardware RNG.
*/
class BOTAN_PUBLIC_API(2,0) Stateful_RNG : public RandomNumberGenerator
   {
   public:
      /**
      * @param rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      Stateful_RNG(RandomNumberGenerator& rng,
                   Entropy_Sources& entropy_sources,
                   size_t reseed_interval) :
         m_underlying_rng(&rng),
         m_entropy_sources(&entropy_sources),
         m_reseed_interval(reseed_interval)
         {}

      /**
      * @param rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      Stateful_RNG(RandomNumberGenerator& rng, size_t reseed_interval) :
         m_underlying_rng(&rng),
         m_reseed_interval(reseed_interval)
         {}

      /**
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed
      */
      Stateful_RNG(Entropy_Sources& entropy_sources, size_t reseed_interval) :
         m_entropy_sources(&entropy_sources),
         m_reseed_interval(reseed_interval)
         {}

      /**
      * In this case, automatic reseeding is impossible
      */
      Stateful_RNG() : m_reseed_interval(0) {}

      /**
      * Consume this input and mark the RNG as initialized regardless
      * of the length of the input or the current seeded state of
      * the RNG.
      */
      void initialize_with(const uint8_t input[], size_t length);

      bool is_seeded() const override final;

      bool accepts_input() const override final { return true; }

      /**
      * Mark state as requiring a reseed on next use
      */
      void force_reseed();

      void reseed_from_rng(RandomNumberGenerator& rng,
                           size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS) override final;

      void add_entropy(const uint8_t input[], size_t input_len) override final;

      void randomize(uint8_t output[], size_t output_len) override final;

      void randomize_with_input(uint8_t output[], size_t output_len,
                                const uint8_t input[], size_t input_len) override final;

      /**
      * Overrides default implementation and also includes the current
      * process ID and the reseed counter.
      */
      void randomize_with_ts_input(uint8_t output[], size_t output_len) override final;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      */
      size_t reseed(Entropy_Sources& srcs,
                    size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                    std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override;

      /**
      * @return intended security level of this DRBG
      */
      virtual size_t security_level() const = 0;

      /**
      * Some DRBGs have a notion of the maximum number of bytes per
      * request.  Longer requests (to randomize) will be treated as
      * multiple requests, and may initiate reseeding multiple times,
      * depending on the values of max_number_of_bytes_per_request and
      * reseed_interval(). This function returns zero if the RNG in
      * question does not have such a notion.
      *
      * @return max number of bytes per request (or zero)
      */
      virtual size_t max_number_of_bytes_per_request() const = 0;

      size_t reseed_interval() const { return m_reseed_interval; }

      void clear() override final;

   protected:
      void reseed_check();

      virtual void generate_output(uint8_t output[], size_t output_len,
                                   const uint8_t input[], size_t input_len) = 0;

      virtual void update(const uint8_t input[], size_t input_len) = 0;

      virtual void clear_state() = 0;

   private:
      void reset_reseed_counter();

      mutable recursive_mutex_type m_mutex;

      // A non-owned and possibly null pointer to shared RNG
      RandomNumberGenerator* m_underlying_rng = nullptr;

      // A non-owned and possibly null pointer to a shared Entropy_Source
      Entropy_Sources* m_entropy_sources = nullptr;

      const size_t m_reseed_interval;
      uint32_t m_last_pid = 0;

      /*
      * Set to 1 after a successful seeding, then incremented.  Reset
      * to 0 by clear() or a fork. This logic is used even if
      * automatic reseeding is disabled (via m_reseed_interval = 0)
      */
      size_t m_reseed_counter = 0;
   };

}

namespace Botan {

class Entropy_Sources;

/**
* HMAC_DRBG from NIST SP800-90A
*/
class BOTAN_PUBLIC_API(2,0) HMAC_DRBG final : public Stateful_RNG
   {
   public:
      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * Automatic reseeding is disabled completely, as it has no access to
      * any source for seed material.
      *
      * If a fork is detected, the RNG will be unable to reseed itself
      * in response. In this case, an exception will be thrown rather
      * than generating duplicated output.
      */
      explicit HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf);

      /**
      * Constructor taking a string for the hash
      */
      explicit HMAC_DRBG(const std::string& hmac_hash);

      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * Automatic reseeding from @p underlying_rng will take place after
      * @p reseed_interval many requests or after a fork was detected.
      *
      * @param prf MAC to use as a PRF
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed (max. 2^24)
      * @param max_number_of_bytes_per_request requests that are in size higher
      * than max_number_of_bytes_per_request are treated as if multiple single
      * requests of max_number_of_bytes_per_request size had been made.
      * In theory SP 800-90A requires that we reject any request for a DRBG
      * output longer than max_number_of_bytes_per_request. To avoid inconveniencing
      * the caller who wants an output larger than max_number_of_bytes_per_request,
      * instead treat these requests as if multiple requests of
      * max_number_of_bytes_per_request size had been made. NIST requires for
      * HMAC_DRBG that every implementation set a value no more than 2**19 bits
      * (or 64 KiB). Together with @p reseed_interval = 1 you can enforce that for
      * example every 512 bit automatic reseeding occurs.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                RandomNumberGenerator& underlying_rng,
                size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL,
                size_t max_number_of_bytes_per_request = 64 * 1024);

      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * Automatic reseeding from @p entropy_sources will take place after
      * @p reseed_interval many requests or after a fork was detected.
      *
      * @param prf MAC to use as a PRF
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed (max. 2^24)
      * @param max_number_of_bytes_per_request requests that are in size higher
      * than max_number_of_bytes_per_request are treated as if multiple single
      * requests of max_number_of_bytes_per_request size had been made.
      * In theory SP 800-90A requires that we reject any request for a DRBG
      * output longer than max_number_of_bytes_per_request. To avoid inconveniencing
      * the caller who wants an output larger than max_number_of_bytes_per_request,
      * instead treat these requests as if multiple requests of
      * max_number_of_bytes_per_request size had been made. NIST requires for
      * HMAC_DRBG that every implementation set a value no more than 2**19 bits
      * (or 64 KiB). Together with @p reseed_interval = 1 you can enforce that for
      * example every 512 bit automatic reseeding occurs.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                Entropy_Sources& entropy_sources,
                size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL,
                size_t max_number_of_bytes_per_request = 64 * 1024);

      /**
      * Initialize an HMAC_DRBG instance with the given MAC as PRF (normally HMAC)
      *
      * Automatic reseeding from @p underlying_rng and @p entropy_sources
      * will take place after @p reseed_interval many requests or after
      * a fork was detected.
      *
      * @param prf MAC to use as a PRF
      * @param underlying_rng is a reference to some RNG which will be used
      * to perform the periodic reseeding
      * @param entropy_sources will be polled to perform reseeding periodically
      * @param reseed_interval specifies a limit of how many times
      * the RNG will be called before automatic reseeding is performed (max. 2^24)
      * @param max_number_of_bytes_per_request requests that are in size higher
      * than max_number_of_bytes_per_request are treated as if multiple single
      * requests of max_number_of_bytes_per_request size had been made.
      * In theory SP 800-90A requires that we reject any request for a DRBG
      * output longer than max_number_of_bytes_per_request. To avoid inconveniencing
      * the caller who wants an output larger than max_number_of_bytes_per_request,
      * instead treat these requests as if multiple requests of
      * max_number_of_bytes_per_request size had been made. NIST requires for
      * HMAC_DRBG that every implementation set a value no more than 2**19 bits
      * (or 64 KiB). Together with @p reseed_interval = 1 you can enforce that for
      * example every 512 bit automatic reseeding occurs.
      */
      HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                RandomNumberGenerator& underlying_rng,
                Entropy_Sources& entropy_sources,
                size_t reseed_interval = BOTAN_RNG_DEFAULT_RESEED_INTERVAL,
                size_t max_number_of_bytes_per_request = 64 * 1024);

      std::string name() const override;

      size_t security_level() const override;

      size_t max_number_of_bytes_per_request() const override
         { return m_max_number_of_bytes_per_request; }

   private:
      void update(const uint8_t input[], size_t input_len) override;

      void generate_output(uint8_t output[], size_t output_len,
                           const uint8_t input[], size_t input_len) override;

      void clear_state() override;

      std::unique_ptr<MessageAuthenticationCode> m_mac;
      secure_vector<uint8_t> m_V;
      const size_t m_max_number_of_bytes_per_request;
      const size_t m_security_level;
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(loadstor.h)

#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   #define BOTAN_ENDIAN_N2L(x) reverse_bytes(x)
   #define BOTAN_ENDIAN_L2N(x) reverse_bytes(x)
   #define BOTAN_ENDIAN_N2B(x) (x)
   #define BOTAN_ENDIAN_B2N(x) (x)

#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   #define BOTAN_ENDIAN_N2L(x) (x)
   #define BOTAN_ENDIAN_L2N(x) (x)
   #define BOTAN_ENDIAN_N2B(x) reverse_bytes(x)
   #define BOTAN_ENDIAN_B2N(x) reverse_bytes(x)

#endif

namespace Botan {

/**
* Byte extraction
* @param byte_num which byte to extract, 0 == highest byte
* @param input the value to extract from
* @return byte byte_num of input
*/
template<typename T> inline constexpr uint8_t get_byte(size_t byte_num, T input)
   {
   return static_cast<uint8_t>(
      input >> (((~byte_num)&(sizeof(T)-1)) << 3)
      );
   }

/**
* Make a uint16_t from two bytes
* @param i0 the first byte
* @param i1 the second byte
* @return i0 || i1
*/
inline constexpr uint16_t make_uint16(uint8_t i0, uint8_t i1)
   {
   return static_cast<uint16_t>((static_cast<uint16_t>(i0) << 8) | i1);
   }

/**
* Make a uint32_t from four bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @return i0 || i1 || i2 || i3
*/
inline constexpr uint32_t make_uint32(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3)
   {
   return ((static_cast<uint32_t>(i0) << 24) |
           (static_cast<uint32_t>(i1) << 16) |
           (static_cast<uint32_t>(i2) <<  8) |
           (static_cast<uint32_t>(i3)));
   }

/**
* Make a uint64_t from eight bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @param i4 the fifth byte
* @param i5 the sixth byte
* @param i6 the seventh byte
* @param i7 the eighth byte
* @return i0 || i1 || i2 || i3 || i4 || i5 || i6 || i7
*/
inline constexpr uint64_t make_uint64(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3,
                                      uint8_t i4, uint8_t i5, uint8_t i6, uint8_t i7)
    {
   return ((static_cast<uint64_t>(i0) << 56) |
           (static_cast<uint64_t>(i1) << 48) |
           (static_cast<uint64_t>(i2) << 40) |
           (static_cast<uint64_t>(i3) << 32) |
           (static_cast<uint64_t>(i4) << 24) |
           (static_cast<uint64_t>(i5) << 16) |
           (static_cast<uint64_t>(i6) <<  8) |
           (static_cast<uint64_t>(i7)));
    }

/**
* Load a big-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a big-endian value
*/
template<typename T>
inline T load_be(const uint8_t in[], size_t off)
   {
   in += off * sizeof(T);
   T out = 0;
   for(size_t i = 0; i != sizeof(T); ++i)
      out = static_cast<T>((out << 8) | in[i]);
   return out;
   }

/**
* Load a little-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a litte-endian value
*/
template<typename T>
inline T load_le(const uint8_t in[], size_t off)
   {
   in += off * sizeof(T);
   T out = 0;
   for(size_t i = 0; i != sizeof(T); ++i)
      out = (out << 8) | in[sizeof(T)-1-i];
   return out;
   }

/**
* Load a big-endian uint16_t
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint16_t of in, as a big-endian value
*/
template<>
inline uint16_t load_be<uint16_t>(const uint8_t in[], size_t off)
   {
   in += off * sizeof(uint16_t);

#if defined(BOTAN_ENDIAN_N2B)
   uint16_t x;
   typecast_copy(x, in);
   return BOTAN_ENDIAN_N2B(x);
#else
   return make_uint16(in[0], in[1]);
#endif
   }

/**
* Load a little-endian uint16_t
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint16_t of in, as a little-endian value
*/
template<>
inline uint16_t load_le<uint16_t>(const uint8_t in[], size_t off)
   {
   in += off * sizeof(uint16_t);

#if defined(BOTAN_ENDIAN_N2L)
   uint16_t x;
   typecast_copy(x, in);
   return BOTAN_ENDIAN_N2L(x);
#else
   return make_uint16(in[1], in[0]);
#endif
   }

/**
* Load a big-endian uint32_t
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint32_t of in, as a big-endian value
*/
template<>
inline uint32_t load_be<uint32_t>(const uint8_t in[], size_t off)
   {
   in += off * sizeof(uint32_t);
#if defined(BOTAN_ENDIAN_N2B)
   uint32_t x;
   typecast_copy(x, in);
   return BOTAN_ENDIAN_N2B(x);
#else
   return make_uint32(in[0], in[1], in[2], in[3]);
#endif
   }

/**
* Load a little-endian uint32_t
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint32_t of in, as a little-endian value
*/
template<>
inline uint32_t load_le<uint32_t>(const uint8_t in[], size_t off)
   {
   in += off * sizeof(uint32_t);
#if defined(BOTAN_ENDIAN_N2L)
   uint32_t x;
   typecast_copy(x, in);
   return BOTAN_ENDIAN_N2L(x);
#else
   return make_uint32(in[3], in[2], in[1], in[0]);
#endif
   }

/**
* Load a big-endian uint64_t
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint64_t of in, as a big-endian value
*/
template<>
inline uint64_t load_be<uint64_t>(const uint8_t in[], size_t off)
   {
   in += off * sizeof(uint64_t);
#if defined(BOTAN_ENDIAN_N2B)
   uint64_t x;
   typecast_copy(x, in);
   return BOTAN_ENDIAN_N2B(x);
#else
   return make_uint64(in[0], in[1], in[2], in[3],
                      in[4], in[5], in[6], in[7]);
#endif
   }

/**
* Load a little-endian uint64_t
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint64_t of in, as a little-endian value
*/
template<>
inline uint64_t load_le<uint64_t>(const uint8_t in[], size_t off)
   {
   in += off * sizeof(uint64_t);
#if defined(BOTAN_ENDIAN_N2L)
   uint64_t x;
   typecast_copy(x, in);
   return BOTAN_ENDIAN_N2L(x);
#else
   return make_uint64(in[7], in[6], in[5], in[4],
                      in[3], in[2], in[1], in[0]);
#endif
   }

/**
* Load two little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
template<typename T>
inline void load_le(const uint8_t in[], T& x0, T& x1)
   {
   x0 = load_le<T>(in, 0);
   x1 = load_le<T>(in, 1);
   }

/**
* Load four little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
template<typename T>
inline void load_le(const uint8_t in[],
                    T& x0, T& x1, T& x2, T& x3)
   {
   x0 = load_le<T>(in, 0);
   x1 = load_le<T>(in, 1);
   x2 = load_le<T>(in, 2);
   x3 = load_le<T>(in, 3);
   }

/**
* Load eight little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
* @param x4 where the fifth word will be written
* @param x5 where the sixth word will be written
* @param x6 where the seventh word will be written
* @param x7 where the eighth word will be written
*/
template<typename T>
inline void load_le(const uint8_t in[],
                    T& x0, T& x1, T& x2, T& x3,
                    T& x4, T& x5, T& x6, T& x7)
   {
   x0 = load_le<T>(in, 0);
   x1 = load_le<T>(in, 1);
   x2 = load_le<T>(in, 2);
   x3 = load_le<T>(in, 3);
   x4 = load_le<T>(in, 4);
   x5 = load_le<T>(in, 5);
   x6 = load_le<T>(in, 6);
   x7 = load_le<T>(in, 7);
   }

/**
* Load a variable number of little-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
template<typename T>
inline void load_le(T out[],
                    const uint8_t in[],
                    size_t count)
   {
   if(count > 0)
      {
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      typecast_copy(out, in, count);

#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      typecast_copy(out, in, count);

      const size_t blocks = count - (count % 4);
      const size_t left = count - blocks;

      for(size_t i = 0; i != blocks; i += 4)
         bswap_4(out + i);

      for(size_t i = 0; i != left; ++i)
         out[blocks+i] = reverse_bytes(out[blocks+i]);
#else
      for(size_t i = 0; i != count; ++i)
         out[i] = load_le<T>(in, i);
#endif
      }
   }

/**
* Load two big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
template<typename T>
inline void load_be(const uint8_t in[], T& x0, T& x1)
   {
   x0 = load_be<T>(in, 0);
   x1 = load_be<T>(in, 1);
   }

/**
* Load four big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
template<typename T>
inline void load_be(const uint8_t in[],
                    T& x0, T& x1, T& x2, T& x3)
   {
   x0 = load_be<T>(in, 0);
   x1 = load_be<T>(in, 1);
   x2 = load_be<T>(in, 2);
   x3 = load_be<T>(in, 3);
   }

/**
* Load eight big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
* @param x4 where the fifth word will be written
* @param x5 where the sixth word will be written
* @param x6 where the seventh word will be written
* @param x7 where the eighth word will be written
*/
template<typename T>
inline void load_be(const uint8_t in[],
                    T& x0, T& x1, T& x2, T& x3,
                    T& x4, T& x5, T& x6, T& x7)
   {
   x0 = load_be<T>(in, 0);
   x1 = load_be<T>(in, 1);
   x2 = load_be<T>(in, 2);
   x3 = load_be<T>(in, 3);
   x4 = load_be<T>(in, 4);
   x5 = load_be<T>(in, 5);
   x6 = load_be<T>(in, 6);
   x7 = load_be<T>(in, 7);
   }

/**
* Load a variable number of big-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
template<typename T>
inline void load_be(T out[],
                    const uint8_t in[],
                    size_t count)
   {
   if(count > 0)
      {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
      typecast_copy(out, in, count);

#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
      typecast_copy(out, in, count);
      const size_t blocks = count - (count % 4);
      const size_t left = count - blocks;

      for(size_t i = 0; i != blocks; i += 4)
         bswap_4(out + i);

      for(size_t i = 0; i != left; ++i)
         out[blocks+i] = reverse_bytes(out[blocks+i]);
#else
      for(size_t i = 0; i != count; ++i)
         out[i] = load_be<T>(in, i);
#endif
      }
   }

/**
* Store a big-endian uint16_t
* @param in the input uint16_t
* @param out the byte array to write to
*/
inline void store_be(uint16_t in, uint8_t out[2])
   {
#if defined(BOTAN_ENDIAN_N2B)
   uint16_t o = BOTAN_ENDIAN_N2B(in);
   typecast_copy(out, o);
#else
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
#endif
   }

/**
* Store a little-endian uint16_t
* @param in the input uint16_t
* @param out the byte array to write to
*/
inline void store_le(uint16_t in, uint8_t out[2])
   {
#if defined(BOTAN_ENDIAN_N2L)
   uint16_t o = BOTAN_ENDIAN_N2L(in);
   typecast_copy(out, o);
#else
   out[0] = get_byte(1, in);
   out[1] = get_byte(0, in);
#endif
   }

/**
* Store a big-endian uint32_t
* @param in the input uint32_t
* @param out the byte array to write to
*/
inline void store_be(uint32_t in, uint8_t out[4])
   {
#if defined(BOTAN_ENDIAN_B2N)
   uint32_t o = BOTAN_ENDIAN_B2N(in);
   typecast_copy(out, o);
#else
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
#endif
   }

/**
* Store a little-endian uint32_t
* @param in the input uint32_t
* @param out the byte array to write to
*/
inline void store_le(uint32_t in, uint8_t out[4])
   {
#if defined(BOTAN_ENDIAN_L2N)
   uint32_t o = BOTAN_ENDIAN_L2N(in);
   typecast_copy(out, o);
#else
   out[0] = get_byte(3, in);
   out[1] = get_byte(2, in);
   out[2] = get_byte(1, in);
   out[3] = get_byte(0, in);
#endif
   }

/**
* Store a big-endian uint64_t
* @param in the input uint64_t
* @param out the byte array to write to
*/
inline void store_be(uint64_t in, uint8_t out[8])
   {
#if defined(BOTAN_ENDIAN_B2N)
   uint64_t o = BOTAN_ENDIAN_B2N(in);
   typecast_copy(out, o);
#else
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
   out[4] = get_byte(4, in);
   out[5] = get_byte(5, in);
   out[6] = get_byte(6, in);
   out[7] = get_byte(7, in);
#endif
   }

/**
* Store a little-endian uint64_t
* @param in the input uint64_t
* @param out the byte array to write to
*/
inline void store_le(uint64_t in, uint8_t out[8])
   {
#if defined(BOTAN_ENDIAN_L2N)
   uint64_t o = BOTAN_ENDIAN_L2N(in);
   typecast_copy(out, o);
#else
   out[0] = get_byte(7, in);
   out[1] = get_byte(6, in);
   out[2] = get_byte(5, in);
   out[3] = get_byte(4, in);
   out[4] = get_byte(3, in);
   out[5] = get_byte(2, in);
   out[6] = get_byte(1, in);
   out[7] = get_byte(0, in);
#endif
   }

/**
* Store two little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
template<typename T>
inline void store_le(uint8_t out[], T x0, T x1)
   {
   store_le(x0, out + (0 * sizeof(T)));
   store_le(x1, out + (1 * sizeof(T)));
   }

/**
* Store two big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
template<typename T>
inline void store_be(uint8_t out[], T x0, T x1)
   {
   store_be(x0, out + (0 * sizeof(T)));
   store_be(x1, out + (1 * sizeof(T)));
   }

/**
* Store four little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
template<typename T>
inline void store_le(uint8_t out[], T x0, T x1, T x2, T x3)
   {
   store_le(x0, out + (0 * sizeof(T)));
   store_le(x1, out + (1 * sizeof(T)));
   store_le(x2, out + (2 * sizeof(T)));
   store_le(x3, out + (3 * sizeof(T)));
   }

/**
* Store four big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
template<typename T>
inline void store_be(uint8_t out[], T x0, T x1, T x2, T x3)
   {
   store_be(x0, out + (0 * sizeof(T)));
   store_be(x1, out + (1 * sizeof(T)));
   store_be(x2, out + (2 * sizeof(T)));
   store_be(x3, out + (3 * sizeof(T)));
   }

/**
* Store eight little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
* @param x4 the fifth word
* @param x5 the sixth word
* @param x6 the seventh word
* @param x7 the eighth word
*/
template<typename T>
inline void store_le(uint8_t out[], T x0, T x1, T x2, T x3,
                                 T x4, T x5, T x6, T x7)
   {
   store_le(x0, out + (0 * sizeof(T)));
   store_le(x1, out + (1 * sizeof(T)));
   store_le(x2, out + (2 * sizeof(T)));
   store_le(x3, out + (3 * sizeof(T)));
   store_le(x4, out + (4 * sizeof(T)));
   store_le(x5, out + (5 * sizeof(T)));
   store_le(x6, out + (6 * sizeof(T)));
   store_le(x7, out + (7 * sizeof(T)));
   }

/**
* Store eight big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
* @param x4 the fifth word
* @param x5 the sixth word
* @param x6 the seventh word
* @param x7 the eighth word
*/
template<typename T>
inline void store_be(uint8_t out[], T x0, T x1, T x2, T x3,
                                 T x4, T x5, T x6, T x7)
   {
   store_be(x0, out + (0 * sizeof(T)));
   store_be(x1, out + (1 * sizeof(T)));
   store_be(x2, out + (2 * sizeof(T)));
   store_be(x3, out + (3 * sizeof(T)));
   store_be(x4, out + (4 * sizeof(T)));
   store_be(x5, out + (5 * sizeof(T)));
   store_be(x6, out + (6 * sizeof(T)));
   store_be(x7, out + (7 * sizeof(T)));
   }

template<typename T>
void copy_out_be(uint8_t out[], size_t out_bytes, const T in[])
   {
   while(out_bytes >= sizeof(T))
      {
      store_be(in[0], out);
      out += sizeof(T);
      out_bytes -= sizeof(T);
      in += 1;
   }

   for(size_t i = 0; i != out_bytes; ++i)
      out[i] = get_byte(i%8, in[0]);
   }

template<typename T, typename Alloc>
void copy_out_vec_be(uint8_t out[], size_t out_bytes, const std::vector<T, Alloc>& in)
   {
   copy_out_be(out, out_bytes, in.data());
   }

template<typename T>
void copy_out_le(uint8_t out[], size_t out_bytes, const T in[])
   {
   while(out_bytes >= sizeof(T))
      {
      store_le(in[0], out);
      out += sizeof(T);
      out_bytes -= sizeof(T);
      in += 1;
   }

   for(size_t i = 0; i != out_bytes; ++i)
      out[i] = get_byte(sizeof(T) - 1 - (i % 8), in[0]);
   }

template<typename T, typename Alloc>
void copy_out_vec_le(uint8_t out[], size_t out_bytes, const std::vector<T, Alloc>& in)
   {
   copy_out_le(out, out_bytes, in.data());
   }

}

BOTAN_FUTURE_INTERNAL_HEADER(mdx_hash.h)

namespace Botan {

/**
* MDx Hash Function Base Class
*/
class BOTAN_PUBLIC_API(2,0) MDx_HashFunction : public HashFunction
   {
   public:
      /**
      * @param block_length is the number of bytes per block, which must
      *        be a power of 2 and at least 8.
      * @param big_byte_endian specifies if the hash uses big-endian bytes
      * @param big_bit_endian specifies if the hash uses big-endian bits
      * @param counter_size specifies the size of the counter var in bytes
      */
      MDx_HashFunction(size_t block_length,
                       bool big_byte_endian,
                       bool big_bit_endian,
                       uint8_t counter_size = 8);

      size_t hash_block_size() const override final { return m_buffer.size(); }
   protected:
      void add_data(const uint8_t input[], size_t length) override final;
      void final_result(uint8_t output[]) override final;

      /**
      * Run the hash's compression function over a set of blocks
      * @param blocks the input
      * @param block_n the number of blocks
      */
      virtual void compress_n(const uint8_t blocks[], size_t block_n) = 0;

      void clear() override;

      /**
      * Copy the output to the buffer
      * @param buffer to put the output into
      */
      virtual void copy_out(uint8_t buffer[]) = 0;

      /**
      * Write the count, if used, to this spot
      * @param out where to write the counter to
      */
      virtual void write_count(uint8_t out[]);
   private:
      const uint8_t m_pad_char;
      const uint8_t m_counter_size;
      const uint8_t m_block_bits;
      const bool m_count_big_endian;

      uint64_t m_count;
      secure_vector<uint8_t> m_buffer;
      size_t m_position;
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(md5.h)

namespace Botan {

/**
* MD5
*/
class BOTAN_PUBLIC_API(2,0) MD5 final : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "MD5"; }
      size_t output_length() const override { return 16; }
      HashFunction* clone() const override { return new MD5; }
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      MD5() : MDx_HashFunction(64, false, true), m_M(16), m_digest(4)
         { clear(); }

   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      /**
      * The message buffer
      */
      secure_vector<uint32_t> m_M;

      /**
      * The digest value
      */
      secure_vector<uint32_t> m_digest;
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(mul128.h)

namespace Botan {

#if defined(__SIZEOF_INT128__) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)
   #define BOTAN_TARGET_HAS_NATIVE_UINT128

   // Prefer TI mode over __int128 as GCC rejects the latter in pendantic mode
   #if defined(__GNUG__)
     typedef unsigned int uint128_t __attribute__((mode(TI)));
   #else
     typedef unsigned __int128 uint128_t;
   #endif
#endif

}

#if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)

#define BOTAN_FAST_64X64_MUL(a,b,lo,hi)      \
   do {                                      \
      const uint128_t r = static_cast<uint128_t>(a) * b;   \
      *hi = (r >> 64) & 0xFFFFFFFFFFFFFFFF;  \
      *lo = (r      ) & 0xFFFFFFFFFFFFFFFF;  \
   } while(0)

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC) && defined(BOTAN_TARGET_CPU_HAS_NATIVE_64BIT)

#include <intrin.h>
#if defined(_M_ARM64)
#pragma intrinsic(__umulh)
#else
#pragma intrinsic(_umul128)
#endif

#if defined(_M_ARM64)
#define BOTAN_FAST_64X64_MUL(a,b,lo,hi) \
   do { *lo = a * b; *hi = __umulh(a, b); } while(0)
#else
#define BOTAN_FAST_64X64_MUL(a,b,lo,hi) \
   do { *lo = _umul128(a, b, hi); } while(0)
#endif

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

#if defined(BOTAN_TARGET_ARCH_IS_X86_64)

#define BOTAN_FAST_64X64_MUL(a,b,lo,hi) do {                           \
   asm("mulq %3" : "=d" (*hi), "=a" (*lo) : "a" (a), "rm" (b) : "cc"); \
   } while(0)

#elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)

#define BOTAN_FAST_64X64_MUL(a,b,lo,hi) do {              \
   asm("umulh %1,%2,%0" : "=r" (*hi) : "r" (a), "r" (b)); \
   *lo = a * b;                                           \
} while(0)

#elif defined(BOTAN_TARGET_ARCH_IS_IA64)

#define BOTAN_FAST_64X64_MUL(a,b,lo,hi) do {                \
   asm("xmpy.hu %0=%1,%2" : "=f" (*hi) : "f" (a), "f" (b)); \
   *lo = a * b;                                             \
} while(0)

#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)

#define BOTAN_FAST_64X64_MUL(a,b,lo,hi) do {                      \
   asm("mulhdu %0,%1,%2" : "=r" (*hi) : "r" (a), "r" (b) : "cc"); \
   *lo = a * b;                                                   \
} while(0)

#endif

#endif

namespace Botan {

/**
* Perform a 64x64->128 bit multiplication
*/
inline void mul64x64_128(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi)
   {
#if defined(BOTAN_FAST_64X64_MUL)
   BOTAN_FAST_64X64_MUL(a, b, lo, hi);
#else

   /*
   * Do a 64x64->128 multiply using four 32x32->64 multiplies plus
   * some adds and shifts. Last resort for CPUs like UltraSPARC (with
   * 64-bit registers/ALU, but no 64x64->128 multiply) or 32-bit CPUs.
   */
   const size_t HWORD_BITS = 32;
   const uint32_t HWORD_MASK = 0xFFFFFFFF;

   const uint32_t a_hi = (a >> HWORD_BITS);
   const uint32_t a_lo = (a  & HWORD_MASK);
   const uint32_t b_hi = (b >> HWORD_BITS);
   const uint32_t b_lo = (b  & HWORD_MASK);

   uint64_t x0 = static_cast<uint64_t>(a_hi) * b_hi;
   uint64_t x1 = static_cast<uint64_t>(a_lo) * b_hi;
   uint64_t x2 = static_cast<uint64_t>(a_hi) * b_lo;
   uint64_t x3 = static_cast<uint64_t>(a_lo) * b_lo;

   // this cannot overflow as (2^32-1)^2 + 2^32-1 < 2^64-1
   x2 += x3 >> HWORD_BITS;

   // this one can overflow
   x2 += x1;

   // propagate the carry if any
   x0 += static_cast<uint64_t>(static_cast<bool>(x2 < x1)) << HWORD_BITS;

   *hi = x0 + (x2 >> HWORD_BITS);
   *lo  = ((x2 & HWORD_MASK) << HWORD_BITS) + (x3 & HWORD_MASK);
#endif
   }

}


BOTAN_FUTURE_INTERNAL_HEADER(parsing.h)

namespace Botan {

/**
* Parse a SCAN-style algorithm name
* @param scan_name the name
* @return the name components
*/
BOTAN_PUBLIC_API(2,0) std::vector<std::string>
parse_algorithm_name(const std::string& scan_name);

/**
* Split a string
* @param str the input string
* @param delim the delimitor
* @return string split by delim
*/
BOTAN_PUBLIC_API(2,0) std::vector<std::string> split_on(
   const std::string& str, char delim);

/**
* Split a string on a character predicate
* @param str the input string
* @param pred the predicate
*
* This function will likely be removed in a future release
*/
BOTAN_PUBLIC_API(2,0) std::vector<std::string>
split_on_pred(const std::string& str,
              std::function<bool (char)> pred);

/**
* Erase characters from a string
*/
BOTAN_PUBLIC_API(2,0)
BOTAN_DEPRECATED("Unused")
std::string erase_chars(const std::string& str, const std::set<char>& chars);

/**
* Replace a character in a string
* @param str the input string
* @param from_char the character to replace
* @param to_char the character to replace it with
* @return str with all instances of from_char replaced by to_char
*/
BOTAN_PUBLIC_API(2,0)
BOTAN_DEPRECATED("Unused")
std::string replace_char(const std::string& str,
                         char from_char,
                         char to_char);

/**
* Replace a character in a string
* @param str the input string
* @param from_chars the characters to replace
* @param to_char the character to replace it with
* @return str with all instances of from_chars replaced by to_char
*/
BOTAN_PUBLIC_API(2,0)
BOTAN_DEPRECATED("Unused")
std::string replace_chars(const std::string& str,
                          const std::set<char>& from_chars,
                          char to_char);

/**
* Join a string
* @param strs strings to join
* @param delim the delimitor
* @return string joined by delim
*/
BOTAN_PUBLIC_API(2,0)
std::string string_join(const std::vector<std::string>& strs,
                        char delim);

/**
* Parse an ASN.1 OID
* @param oid the OID in string form
* @return OID components
*/
BOTAN_PUBLIC_API(2,0) std::vector<uint32_t>
BOTAN_DEPRECATED("Use OID::from_string(oid).get_components()") parse_asn1_oid(const std::string& oid);

/**
* Compare two names using the X.509 comparison algorithm
* @param name1 the first name
* @param name2 the second name
* @return true if name1 is the same as name2 by the X.509 comparison rules
*/
BOTAN_PUBLIC_API(2,0)
bool x500_name_cmp(const std::string& name1,
                   const std::string& name2);

/**
* Convert a string to a number
* @param str the string to convert
* @return number value of the string
*/
BOTAN_PUBLIC_API(2,0) uint32_t to_u32bit(const std::string& str);

/**
* Convert a string to a number
* @param str the string to convert
* @return number value of the string
*/
BOTAN_PUBLIC_API(2,3) uint16_t to_uint16(const std::string& str);

/**
* Convert a time specification to a number
* @param timespec the time specification
* @return number of seconds represented by timespec
*/
BOTAN_PUBLIC_API(2,0) uint32_t BOTAN_DEPRECATED("Not used anymore")
timespec_to_u32bit(const std::string& timespec);

/**
* Convert a string representation of an IPv4 address to a number
* @param ip_str the string representation
* @return integer IPv4 address
*/
BOTAN_PUBLIC_API(2,0) uint32_t string_to_ipv4(const std::string& ip_str);

/**
* Convert an IPv4 address to a string
* @param ip_addr the IPv4 address to convert
* @return string representation of the IPv4 address
*/
BOTAN_PUBLIC_API(2,0) std::string ipv4_to_string(uint32_t ip_addr);

std::map<std::string, std::string> BOTAN_PUBLIC_API(2,0) read_cfg(std::istream& is);

/**
* Accepts key value pairs deliminated by commas:
*
* "" (returns empty map)
* "K=V" (returns map {'K': 'V'})
* "K1=V1,K2=V2"
* "K1=V1,K2=V2,K3=V3"
* "K1=V1,K2=V2,K3=a_value\,with\,commas_and_\=equals"
*
* Values may be empty, keys must be non-empty and unique. Duplicate
* keys cause an exception.
*
* Within both key and value, comma and equals can be escaped with
* backslash. Backslash can also be escaped.
*/
std::map<std::string, std::string> BOTAN_PUBLIC_API(2,8) read_kv(const std::string& kv);

std::string BOTAN_PUBLIC_API(2,0) clean_ws(const std::string& s);

std::string tolower_string(const std::string& s);

/**
* Check if the given hostname is a match for the specified wildcard
*/
bool BOTAN_PUBLIC_API(2,0) host_wildcard_match(const std::string& wildcard,
                                               const std::string& host);


}

BOTAN_FUTURE_INTERNAL_HEADER(rotate.h)

namespace Botan {

/**
* Bit rotation left by a compile-time constant amount
* @param input the input word
* @return input rotated left by ROT bits
*/
template<size_t ROT, typename T>
inline constexpr T rotl(T input)
   {
   static_assert(ROT > 0 && ROT < 8*sizeof(T), "Invalid rotation constant");
   return static_cast<T>((input << ROT) | (input >> (8*sizeof(T) - ROT)));
   }

/**
* Bit rotation right by a compile-time constant amount
* @param input the input word
* @return input rotated right by ROT bits
*/
template<size_t ROT, typename T>
inline constexpr T rotr(T input)
   {
   static_assert(ROT > 0 && ROT < 8*sizeof(T), "Invalid rotation constant");
   return static_cast<T>((input >> ROT) | (input << (8*sizeof(T) - ROT)));
   }

/**
* Bit rotation left, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated left by rot bits
*/
template<typename T>
inline T rotl_var(T input, size_t rot)
   {
   return rot ? static_cast<T>((input << rot) | (input >> (sizeof(T)*8 - rot))) : input;
   }

/**
* Bit rotation right, variable rotation amount
* @param input the input word
* @param rot the number of bits to rotate, must be between 0 and sizeof(T)*8-1
* @return input rotated right by rot bits
*/
template<typename T>
inline T rotr_var(T input, size_t rot)
   {
   return rot ? static_cast<T>((input >> rot) | (input << (sizeof(T)*8 - rot))) : input;
   }

#if defined(BOTAN_USE_GCC_INLINE_ASM)

#if defined(BOTAN_TARGET_ARCH_IS_X86_64) || defined(BOTAN_TARGET_ARCH_IS_X86_32)

template<>
inline uint32_t rotl_var(uint32_t input, size_t rot)
   {
   asm("roll %1,%0"
       : "+r" (input)
       : "c" (static_cast<uint8_t>(rot))
       : "cc");
   return input;
   }

template<>
inline uint32_t rotr_var(uint32_t input, size_t rot)
   {
   asm("rorl %1,%0"
       : "+r" (input)
       : "c" (static_cast<uint8_t>(rot))
       : "cc");
   return input;
   }

#endif

#endif


template<typename T>
BOTAN_DEPRECATED("Use rotl<N> or rotl_var")
inline T rotate_left(T input, size_t rot)
   {
   // rotl_var does not reduce
   return rotl_var(input, rot % (8 * sizeof(T)));
   }

template<typename T>
BOTAN_DEPRECATED("Use rotr<N> or rotr_var")
inline T rotate_right(T input, size_t rot)
   {
   // rotr_var does not reduce
   return rotr_var(input, rot % (8 * sizeof(T)));
   }

}

BOTAN_FUTURE_INTERNAL_HEADER(scan_name.h)

namespace Botan {

/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
class BOTAN_PUBLIC_API(2,0) SCAN_Name final
   {
   public:
      /**
      * Create a SCAN_Name
      * @param algo_spec A SCAN-format name
      */
      explicit SCAN_Name(const char* algo_spec);

      /**
      * Create a SCAN_Name
      * @param algo_spec A SCAN-format name
      */
      explicit SCAN_Name(std::string algo_spec);

      /**
      * @return original input string
      */
      const std::string& to_string() const { return m_orig_algo_spec; }

      BOTAN_DEPRECATED("Use SCAN_Name::to_string") const std::string& as_string() const
         {
         return this->to_string();
         }

      /**
      * @return algorithm name
      */
      const std::string& algo_name() const { return m_alg_name; }

      /**
      * @return number of arguments
      */
      size_t arg_count() const { return m_args.size(); }

      /**
      * @param lower is the lower bound
      * @param upper is the upper bound
      * @return if the number of arguments is between lower and upper
      */
      bool arg_count_between(size_t lower, size_t upper) const
         { return ((arg_count() >= lower) && (arg_count() <= upper)); }

      /**
      * @param i which argument
      * @return ith argument
      */
      std::string arg(size_t i) const;

      /**
      * @param i which argument
      * @param def_value the default value
      * @return ith argument or the default value
      */
      std::string arg(size_t i, const std::string& def_value) const;

      /**
      * @param i which argument
      * @param def_value the default value
      * @return ith argument as an integer, or the default value
      */
      size_t arg_as_integer(size_t i, size_t def_value) const;

      /**
      * @return cipher mode (if any)
      */
      std::string cipher_mode() const
         { return (m_mode_info.size() >= 1) ? m_mode_info[0] : ""; }

      /**
      * @return cipher mode padding (if any)
      */
      std::string cipher_mode_pad() const
         { return (m_mode_info.size() >= 2) ? m_mode_info[1] : ""; }

   private:
      std::string m_orig_algo_spec;
      std::string m_alg_name;
      std::vector<std::string> m_args;
      std::vector<std::string> m_mode_info;
   };

// This is unrelated but it is convenient to stash it here
template<typename T>
std::vector<std::string> probe_providers_of(const std::string& algo_spec,
                                            const std::vector<std::string>& possible)
   {
   std::vector<std::string> providers;
   for(auto&& prov : possible)
      {
      std::unique_ptr<T> o(T::create(algo_spec, prov));
      if(o)
         {
         providers.push_back(prov); // available
         }
      }
   return providers;
   }

}

BOTAN_FUTURE_INTERNAL_HEADER(sha2_32.h)

namespace Botan {

/**
* SHA-224
*/
class BOTAN_PUBLIC_API(2,0) SHA_224 final : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "SHA-224"; }
      size_t output_length() const override { return 28; }
      HashFunction* clone() const override { return new SHA_224; }
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      std::string provider() const override;

      SHA_224() : MDx_HashFunction(64, true, true), m_digest(8)
         { clear(); }
   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      secure_vector<uint32_t> m_digest;
   };

/**
* SHA-256
*/
class BOTAN_PUBLIC_API(2,0) SHA_256 final : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "SHA-256"; }
      size_t output_length() const override { return 32; }
      HashFunction* clone() const override { return new SHA_256; }
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      std::string provider() const override;

      SHA_256() : MDx_HashFunction(64, true, true), m_digest(8)
         { clear(); }

      /*
      * Perform a SHA-256 compression. For internal use
      */
      static void compress_digest(secure_vector<uint32_t>& digest,
                                  const uint8_t input[],
                                  size_t blocks);

   private:

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
      static void compress_digest_armv8(secure_vector<uint32_t>& digest,
                                        const uint8_t input[],
                                        size_t blocks);
#endif

#if defined(BOTAN_HAS_SHA2_32_X86_BMI2)
      static void compress_digest_x86_bmi2(secure_vector<uint32_t>& digest,
                                           const uint8_t input[],
                                           size_t blocks);
#endif

#if defined(BOTAN_HAS_SHA2_32_X86)
      static void compress_digest_x86(secure_vector<uint32_t>& digest,
                                      const uint8_t input[],
                                      size_t blocks);
#endif

      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      secure_vector<uint32_t> m_digest;
   };

}

BOTAN_FUTURE_INTERNAL_HEADER(sha2_64.h)

namespace Botan {

/**
* SHA-384
*/
class BOTAN_PUBLIC_API(2,0) SHA_384 final : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "SHA-384"; }
      size_t output_length() const override { return 48; }
      HashFunction* clone() const override { return new SHA_384; }
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string provider() const override;

      void clear() override;

      SHA_384() : MDx_HashFunction(128, true, true, 16), m_digest(8)
         { clear(); }
   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      secure_vector<uint64_t> m_digest;
   };

/**
* SHA-512
*/
class BOTAN_PUBLIC_API(2,0) SHA_512 final : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "SHA-512"; }
      size_t output_length() const override { return 64; }
      HashFunction* clone() const override { return new SHA_512; }
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string provider() const override;

      void clear() override;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_digest(secure_vector<uint64_t>& digest,
                                  const uint8_t input[],
                                  size_t blocks);

      SHA_512() : MDx_HashFunction(128, true, true, 16), m_digest(8)
         { clear(); }
   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      static const uint64_t K[80];

#if defined(BOTAN_HAS_SHA2_64_BMI2)
      static void compress_digest_bmi2(secure_vector<uint64_t>& digest,
                                       const uint8_t input[],
                                       size_t blocks);
#endif

      secure_vector<uint64_t> m_digest;
   };

/**
* SHA-512/256
*/
class BOTAN_PUBLIC_API(2,0) SHA_512_256 final : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "SHA-512-256"; }
      size_t output_length() const override { return 32; }
      HashFunction* clone() const override { return new SHA_512_256; }
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string provider() const override;

      void clear() override;

      SHA_512_256() : MDx_HashFunction(128, true, true, 16), m_digest(8) { clear(); }
   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      secure_vector<uint64_t> m_digest;
   };

}

#if __cplusplus < 201402L
#endif

BOTAN_FUTURE_INTERNAL_HEADER(stl_compatability.h)

namespace Botan
{
/*
* std::make_unique functionality similar as we have in C++14.
* C++11 version based on proposal for C++14 implemenatation by Stephan T. Lavavej
* source: https://isocpp.org/files/papers/N3656.txt
*/
#if __cplusplus >= 201402L
template <typename T, typename ... Args>
constexpr auto make_unique(Args&&... args)
   {
   return std::make_unique<T>(std::forward<Args>(args)...);
   }

template<class T>
constexpr auto make_unique(std::size_t size)
   {
   return std::make_unique<T>(size);
   }

#else
namespace stlCompatibilityDetails
{
template<class T> struct _Unique_if
   {
   typedef std::unique_ptr<T> _Single_object;
   };

template<class T> struct _Unique_if<T[]>
   {
   typedef std::unique_ptr<T[]> _Unknown_bound;
   };

template<class T, size_t N> struct _Unique_if<T[N]>
   {
   typedef void _Known_bound;
   };
}  // namespace stlCompatibilityDetails

template<class T, class... Args>
typename stlCompatibilityDetails::_Unique_if<T>::_Single_object make_unique(Args&&... args)
   {
   return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
   }

template<class T>
typename stlCompatibilityDetails::_Unique_if<T>::_Unknown_bound make_unique(size_t n)
   {
   typedef typename std::remove_extent<T>::type U;
   return std::unique_ptr<T>(new U[n]());
   }

template<class T, class... Args>
typename stlCompatibilityDetails::_Unique_if<T>::_Known_bound make_unique(Args&&...) = delete;

#endif

}  // namespace Botan

#if defined(BOTAN_HAS_STREAM_CIPHER)
#endif

BOTAN_FUTURE_INTERNAL_HEADER(stream_mode.h)

namespace Botan {

#if defined(BOTAN_HAS_STREAM_CIPHER)

class BOTAN_PUBLIC_API(2,0) Stream_Cipher_Mode final : public Cipher_Mode
   {
   public:
      /**
      * @param cipher underyling stream cipher
      */
      explicit Stream_Cipher_Mode(StreamCipher* cipher) : m_cipher(cipher) {}

      size_t process(uint8_t buf[], size_t sz) override
         {
         m_cipher->cipher1(buf, sz);
         return sz;
         }

      void finish(secure_vector<uint8_t>& buf, size_t offset) override
         { return update(buf, offset); }

      size_t output_length(size_t input_length) const override { return input_length; }

      size_t update_granularity() const override { return 1; }

      size_t minimum_final_size() const override { return 0; }

      size_t default_nonce_length() const override { return 0; }

      bool valid_nonce_length(size_t nonce_len) const override
         { return m_cipher->valid_iv_length(nonce_len); }

      Key_Length_Specification key_spec() const override { return m_cipher->key_spec(); }

      std::string name() const override { return m_cipher->name(); }

      void clear() override
         {
         m_cipher->clear();
         reset();
         }

      void reset() override { /* no msg state */ }

   private:
      void start_msg(const uint8_t nonce[], size_t nonce_len) override
         {
         if(nonce_len > 0)
            {
            m_cipher->set_iv(nonce, nonce_len);
            }
         }

      void key_schedule(const uint8_t key[], size_t length) override
         {
         m_cipher->set_key(key, length);
         }

      std::unique_ptr<StreamCipher> m_cipher;
   };

#endif

}

namespace Botan {

/**
* Return a shared reference to a global PRNG instance provided by the
* operating system. For instance might be instantiated by /dev/urandom
* or CryptGenRandom.
*/
BOTAN_PUBLIC_API(2,0) RandomNumberGenerator& system_rng();

/*
* Instantiable reference to the system RNG.
*/
class BOTAN_PUBLIC_API(2,0) System_RNG final : public RandomNumberGenerator
   {
   public:
      std::string name() const override { return system_rng().name(); }

      void randomize(uint8_t out[], size_t len) override { system_rng().randomize(out, len); }

      void add_entropy(const uint8_t in[], size_t length) override { system_rng().add_entropy(in, length); }

      bool is_seeded() const override { return system_rng().is_seeded(); }

      bool accepts_input() const override { return system_rng().accepts_input(); }

      void clear() override { system_rng().clear(); }
   };

}

namespace Botan {

/*
* Get information describing the version
*/

/**
* Get a human-readable string identifying the version of Botan.
* No particular format should be assumed.
* @return version string
*/
BOTAN_PUBLIC_API(2,0) std::string version_string();

/**
* Same as version_string() except returning a pointer to a statically
* allocated string.
* @return version string
*/
BOTAN_PUBLIC_API(2,0) const char* version_cstr();

/**
* Return a version string of the form "MAJOR.MINOR.PATCH" where
* each of the values is an integer.
*/
BOTAN_PUBLIC_API(2,4) std::string short_version_string();

/**
* Same as version_short_string except returning a pointer to the string.
*/
BOTAN_PUBLIC_API(2,4) const char* short_version_cstr();

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* @return release date, or zero if unreleased
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_datestamp();

/**
* Get the major version number.
* @return major version number
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_major();

/**
* Get the minor version number.
* @return minor version number
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_minor();

/**
* Get the patch number.
* @return patch number
*/
BOTAN_PUBLIC_API(2,0) uint32_t version_patch();

/**
* Usable for checking that the DLL version loaded at runtime exactly
* matches the compile-time version. Call using BOTAN_VERSION_* macro
* values. Returns the empty string if an exact match, otherwise an
* appropriate message. Added with 1.11.26.
*/
BOTAN_PUBLIC_API(2,0) std::string
runtime_version_check(uint32_t major,
                      uint32_t minor,
                      uint32_t patch);

/*
* Macros for compile-time version checks
*/
#define BOTAN_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
*  #    error "Botan version too old"
*  # endif
*/
#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, \
                                                  BOTAN_VERSION_MINOR, \
                                                  BOTAN_VERSION_PATCH)

}

#endif // BOTAN_AMALGAMATION_H_
