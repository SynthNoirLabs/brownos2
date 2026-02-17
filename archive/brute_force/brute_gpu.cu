/*
 * brute_gpu.cu - CUDA GPU-accelerated BrownOS answer hash brute-force
 *
 * Hash verification: sha1^56154(candidate) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
 * Each SHA1 iteration (after the first) operates on the 40-char lowercase hex digest.
 *
 * Compile: nvcc -O3 -arch=sm_86 -o brute_gpu brute_gpu.cu
 * Run:     ./brute_gpu <length> [start_offset]
 *          ./brute_gpu 5         (all 5-char printable ASCII)
 *          ./brute_gpu 5 1000000 (start from candidate #1000000)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ===== Constants ===== */
#define ITERATIONS  56154
#define CHARSET_START 32
#define CHARSET_END   126
#define CHARSET_SIZE  (CHARSET_END - CHARSET_START + 1)  /* 95 */

/* Target hash as 5 x uint32 for fast comparison */
static const uint32_t TARGET_H[5] = {
    0x9252ed65, 0xffac2aa7, 0x63adb21e, 0xf72c0178, 0xf1d83286
};

/* ===== GPU kernel configuration ===== */
#define BLOCK_SIZE  128
#define GRID_SIZE   256
#define BATCH_TOTAL (BLOCK_SIZE * GRID_SIZE)  /* 32768 threads per launch */

/* Progress reporting interval (candidates tested before atomic update) */
#define PROGRESS_CHECK 64

/* ===== SHA1 device implementation ===== */

/* Left-rotate */
__device__ __forceinline__ uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/*
 * sha1_block - Process a single 64-byte SHA1 block.
 * Input: 16 uint32s in W[0..15] (big-endian words of the block)
 * Modifies h0..h4 in place.
 */
__device__ void sha1_block(uint32_t W[16],
                           uint32_t &h0, uint32_t &h1, uint32_t &h2,
                           uint32_t &h3, uint32_t &h4)
{
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    uint32_t f, k, temp;

    /* Rounds 0-79 with message schedule expansion inline */
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        if (i >= 16) {
            W[i & 15] = rotl(W[(i - 3) & 15] ^ W[(i - 8) & 15] ^
                             W[(i - 14) & 15] ^ W[(i - 16) & 15], 1);
        }

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = rotl(a, 5) + f + e + k + W[i & 15];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }

    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
}

/*
 * sha1_short - SHA1 of a short message (<=55 bytes, single block).
 * Writes the 20-byte digest as 5 uint32s.
 */
__device__ void sha1_short(const uint8_t *msg, int len,
                           uint32_t &out0, uint32_t &out1, uint32_t &out2,
                           uint32_t &out3, uint32_t &out4)
{
    uint32_t W[16];

    /* Zero the block */
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = 0;

    /* Copy message bytes into W[] in big-endian */
    for (int i = 0; i < len; i++) {
        W[i >> 2] |= ((uint32_t)msg[i]) << (24 - 8 * (i & 3));
    }

    /* Append bit '1' */
    W[len >> 2] |= ((uint32_t)0x80) << (24 - 8 * (len & 3));

    /* Append length in bits at end of block (word 15 for <=55 byte messages) */
    W[15] = (uint32_t)(len * 8);

    /* Initial hash values */
    out0 = 0x67452301;
    out1 = 0xEFCDAB89;
    out2 = 0x98BADCFE;
    out3 = 0x10325476;
    out4 = 0xC3D2E1F0;

    sha1_block(W, out0, out1, out2, out3, out4);
}

/*
 * sha1_40hex - SHA1 of a 40-byte hex string, given the 5 uint32 hash values
 *              that encode that hex string.
 *
 * This is the hot inner loop - called 56153 times per candidate.
 * The 40-byte hex string is constructed on-the-fly from h0..h4,
 * avoiding the intermediate hex string entirely.
 */
__device__ void sha1_40hex(uint32_t h0, uint32_t h1, uint32_t h2,
                           uint32_t h3, uint32_t h4,
                           uint32_t &o0, uint32_t &o1, uint32_t &o2,
                           uint32_t &o3, uint32_t &o4)
{
    /* Convert 5 hash words (20 bytes) to 40 hex ASCII chars packed in 10 words */
    /* Then pad to fill a 64-byte SHA1 block (16 words) */

    uint32_t W[16];

    /* Hex lookup: ASCII '0'-'9' = 0x30-0x39, 'a'-'f' = 0x61-0x66 */
    /* Each hash byte produces 2 hex chars; each word has 4 bytes -> 8 hex chars -> 2 words */

    /* Helper: convert one uint32 hash word into two uint32 output words (big-endian hex chars) */
    #define HEXWORD(hval, idx) do { \
        uint32_t _v = (hval); \
        uint8_t b0 = (_v >> 24) & 0xFF; \
        uint8_t b1 = (_v >> 16) & 0xFF; \
        uint8_t b2 = (_v >> 8) & 0xFF; \
        uint8_t b3 = _v & 0xFF; \
        uint8_t n0 = b0 >> 4, n1 = b0 & 0xF; \
        uint8_t n2 = b1 >> 4, n3 = b1 & 0xF; \
        uint8_t n4 = b2 >> 4, n5 = b2 & 0xF; \
        uint8_t n6 = b3 >> 4, n7 = b3 & 0xF; \
        uint8_t c0 = n0 < 10 ? (0x30 + n0) : (0x57 + n0); \
        uint8_t c1 = n1 < 10 ? (0x30 + n1) : (0x57 + n1); \
        uint8_t c2 = n2 < 10 ? (0x30 + n2) : (0x57 + n2); \
        uint8_t c3 = n3 < 10 ? (0x30 + n3) : (0x57 + n3); \
        uint8_t c4 = n4 < 10 ? (0x30 + n4) : (0x57 + n4); \
        uint8_t c5 = n5 < 10 ? (0x30 + n5) : (0x57 + n5); \
        uint8_t c6 = n6 < 10 ? (0x30 + n6) : (0x57 + n6); \
        uint8_t c7 = n7 < 10 ? (0x30 + n7) : (0x57 + n7); \
        W[(idx)]   = ((uint32_t)c0 << 24) | ((uint32_t)c1 << 16) | \
                     ((uint32_t)c2 << 8) | (uint32_t)c3; \
        W[(idx)+1] = ((uint32_t)c4 << 24) | ((uint32_t)c5 << 16) | \
                     ((uint32_t)c6 << 8) | (uint32_t)c7; \
    } while(0)

    HEXWORD(h0, 0);
    HEXWORD(h1, 2);
    HEXWORD(h2, 4);
    HEXWORD(h3, 6);
    HEXWORD(h4, 8);

    #undef HEXWORD

    /* Padding for 40-byte message:
     * Byte 40 = 0x80
     * Bytes 41-61 = 0x00
     * Bytes 62-63 = length in bits = 40*8 = 320 = 0x0140
     */
    W[10] = 0x80000000;  /* 0x80 at byte offset 40 */
    W[11] = 0;
    W[12] = 0;
    W[13] = 0;
    W[14] = 0;
    W[15] = 320;         /* 40 * 8 = 320 bits */

    /* SHA1 init */
    o0 = 0x67452301;
    o1 = 0xEFCDAB89;
    o2 = 0x98BADCFE;
    o3 = 0x10325476;
    o4 = 0xC3D2E1F0;

    sha1_block(W, o0, o1, o2, o3, o4);
}

/* ===== Device result communication ===== */
__device__ uint32_t d_found;         /* 0 = not found, 1 = found */
__device__ uint64_t d_found_idx;     /* index of found candidate */
__device__ unsigned long long d_progress; /* atomic progress counter */

/*
 * index_to_candidate - Convert linear index to printable ASCII string.
 * idx is base-95 encoded into buf[0..len-1].
 */
__device__ void index_to_candidate(uint64_t idx, uint8_t *buf, int len) {
    for (int i = len - 1; i >= 0; i--) {
        buf[i] = CHARSET_START + (uint8_t)(idx % CHARSET_SIZE);
        idx /= CHARSET_SIZE;
    }
}

/* ===== Main brute-force kernel ===== */
__global__ void brute_kernel(int str_len, uint64_t total_candidates,
                             uint64_t offset,
                             uint32_t t0, uint32_t t1, uint32_t t2,
                             uint32_t t3, uint32_t t4)
{
    uint64_t gid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;

    for (uint64_t idx = gid + offset; idx < total_candidates; idx += stride) {
        /* Early exit if another thread found it */
        if (d_found) return;

        /* Build candidate string */
        uint8_t candidate[8];
        index_to_candidate(idx, candidate, str_len);

        /* First SHA1: hash the raw candidate bytes */
        uint32_t h0, h1, h2, h3, h4;
        sha1_short(candidate, str_len, h0, h1, h2, h3, h4);

        /* Remaining 56153 iterations: hash the 40-char hex digest */
        for (int i = 1; i < ITERATIONS; i++) {
            uint32_t o0, o1, o2, o3, o4;
            sha1_40hex(h0, h1, h2, h3, h4, o0, o1, o2, o3, o4);
            h0 = o0; h1 = o1; h2 = o2; h3 = o3; h4 = o4;

            /* Check early exit less frequently (every 4096 iterations) */
            if ((i & 0xFFF) == 0 && d_found) return;
        }

        /* Compare to target */
        if (h0 == t0 && h1 == t1 && h2 == t2 && h3 == t3 && h4 == t4) {
            d_found = 1;
            d_found_idx = idx;
            return;
        }

        /* Progress: increment every PROGRESS_CHECK candidates per thread */
        if ((idx & (PROGRESS_CHECK - 1)) == 0) {
            atomicAdd(&d_progress, (unsigned long long)PROGRESS_CHECK);
        }
    }
}

/* ===== Host code ===== */

void index_to_string(uint64_t idx, char *buf, int len) {
    for (int i = len - 1; i >= 0; i--) {
        buf[i] = CHARSET_START + (char)(idx % CHARSET_SIZE);
        idx /= CHARSET_SIZE;
    }
    buf[len] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <length> [start_offset]\n", argv[0]);
        fprintf(stderr, "  length: candidate string length (1-7)\n");
        fprintf(stderr, "  start_offset: skip first N candidates (default 0)\n");
        return 2;
    }

    int str_len = atoi(argv[1]);
    uint64_t start_offset = 0;
    if (argc > 2) {
        start_offset = strtoull(argv[2], NULL, 10);
    }

    if (str_len < 1 || str_len > 7) {
        fprintf(stderr, "String length must be 1-7\n");
        return 2;
    }

    uint64_t total = 1;
    for (int i = 0; i < str_len; i++) total *= CHARSET_SIZE;

    if (start_offset >= total) {
        fprintf(stderr, "Start offset %llu >= total candidates %llu\n",
                (unsigned long long)start_offset, (unsigned long long)total);
        return 2;
    }

    /* GPU info */
    int device;
    cudaDeviceProp prop;
    cudaGetDevice(&device);
    cudaGetDeviceProperties(&prop, device);

    printf("=== BrownOS Answer Hash Brute Force (CUDA) ===\n");
    printf("GPU:        %s (%d SMs, %d cores/SM)\n",
           prop.name, prop.multiProcessorCount,
           /* approximate cores per SM for Ampere */
           128);
    printf("Target:     9252ed65ffac2aa763adb21ef72c0178f1d83286\n");
    printf("Iterations: %d\n", ITERATIONS);
    printf("Str length: %d\n", str_len);
    printf("Charset:    %d-%d (%d printable ASCII chars)\n",
           CHARSET_START, CHARSET_END, CHARSET_SIZE);
    printf("Candidates: %llu\n", (unsigned long long)total);
    if (start_offset > 0) {
        printf("Offset:     %llu (skipping first %llu)\n",
               (unsigned long long)start_offset, (unsigned long long)start_offset);
    }
    printf("Grid:       %d blocks x %d threads = %d threads/launch\n",
           GRID_SIZE, BLOCK_SIZE, BATCH_TOTAL);
    printf("\n");
    fflush(stdout);

    /* Initialize device variables */
    uint32_t zero32 = 0;
    uint64_t zero64 = 0;
    unsigned long long zero_ull = 0;
    cudaMemcpyToSymbol(d_found, &zero32, sizeof(uint32_t));
    cudaMemcpyToSymbol(d_found_idx, &zero64, sizeof(uint64_t));
    cudaMemcpyToSymbol(d_progress, &zero_ull, sizeof(unsigned long long));

    time_t wall_start = time(NULL);
    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* Launch kernel */
    brute_kernel<<<GRID_SIZE, BLOCK_SIZE>>>(
        str_len, total, start_offset,
        TARGET_H[0], TARGET_H[1], TARGET_H[2], TARGET_H[3], TARGET_H[4]
    );

    /* Poll for progress and completion */
    uint32_t found_flag = 0;

    while (1) {
        /* Sleep 2 seconds between polls */
        struct timespec sleep_ts = {2, 0};
        nanosleep(&sleep_ts, NULL);

        /* Check if kernel finished */
        cudaError_t err = cudaStreamQuery(0);

        /* Read progress */
        unsigned long long current_progress;
        cudaMemcpyFromSymbol(&current_progress, d_progress, sizeof(unsigned long long));

        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        double elapsed = (ts_now.tv_sec - ts_start.tv_sec) +
                         (ts_now.tv_nsec - ts_start.tv_nsec) * 1e-9;

        uint64_t remaining = total - start_offset;
        /* Clamp progress to remaining (atomic batching can overshoot) */
        if (current_progress > remaining) current_progress = remaining;
        double pct = (double)current_progress / remaining * 100.0;
        double rate = elapsed > 0 ? current_progress / elapsed : 0;
        double eta = rate > 0 ? (remaining - current_progress) / rate : 0;

        printf("\r[%6.2f%%] %llu / %llu tested | %.0f cand/s | "
               "elapsed %.0fs | ETA %.0fs    ",
               pct, current_progress, (unsigned long long)remaining,
               rate, elapsed, eta);
        fflush(stdout);

        if (err == cudaSuccess) {
            /* Kernel finished */
            break;
        } else if (err != cudaErrorNotReady) {
            fprintf(stderr, "\nCUDA error: %s\n", cudaGetErrorString(err));
            return 3;
        }
    }

    /* Synchronize and check result */
    cudaDeviceSynchronize();

    cudaMemcpyFromSymbol(&found_flag, d_found, sizeof(uint32_t));

    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    double total_time = (ts_now.tv_sec - ts_start.tv_sec) +
                        (ts_now.tv_nsec - ts_start.tv_nsec) * 1e-9;

    printf("\n\n");

    if (found_flag) {
        uint64_t found_idx;
        cudaMemcpyFromSymbol(&found_idx, d_found_idx, sizeof(uint64_t));

        char result[8];
        index_to_string(found_idx, result, str_len);

        printf("*** MATCH FOUND: \"%s\" ***\n", result);
        printf("Index: %llu\n", (unsigned long long)found_idx);
        printf("Hex:   ");
        for (int i = 0; i < str_len; i++) {
            printf("%02x", (unsigned char)result[i]);
        }
        printf("\n");
    } else {
        printf("NO MATCH for %d-char printable ASCII strings\n", str_len);
    }

    printf("Elapsed: %.1f seconds\n", total_time);

    unsigned long long final_progress;
    cudaMemcpyFromSymbol(&final_progress, d_progress, sizeof(unsigned long long));
    if (total_time > 0) {
        printf("Rate:    %.0f candidates/second\n", final_progress / total_time);
    }

    return found_flag ? 0 : 1;
}
