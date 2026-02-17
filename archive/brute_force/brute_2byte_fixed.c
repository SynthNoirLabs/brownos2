#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#define TARGET_HASH "9252ed65ffac2aa763adb21ef72c0178f1d83286"
#define ITERATIONS 56154
#define NUM_THREADS 16

/* Max candidate length to test */
#define MAX_LEN 3

typedef struct {
    uint32_t start;
    uint32_t end;
    int cand_len;
    int found;
    uint32_t match_value;
} thread_args_t;

static volatile int g_found = 0;

void check_candidate(unsigned char *data, int len, uint32_t idx, thread_args_t *args) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    char hex[41];
    
    /* First round: SHA1 of raw candidate bytes */
    SHA1(data, len, hash);
    
    for (int i = 1; i < ITERATIONS; i++) {
        /* Convert hash to lowercase hex string */
        for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
            sprintf(hex + j*2, "%02x", hash[j]);
        hex[40] = '\0';
        
        /* SHA1 of the 40-char hex string */
        SHA1((unsigned char*)hex, 40, hash);
    }
    
    /* Final conversion to hex for comparison */
    for (int j = 0; j < SHA_DIGEST_LENGTH; j++)
        sprintf(hex + j*2, "%02x", hash[j]);
    hex[40] = '\0';
    
    if (strcmp(hex, TARGET_HASH) == 0) {
        printf("\n!!! MATCH FOUND: idx=%u bytes=", idx);
        for (int j = 0; j < len; j++) printf("%02x", data[j]);
        printf(" !!!\n");
        fflush(stdout);
        args->found = 1;
        args->match_value = idx;
        g_found = 1;
    }
}

void* brute_range(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    unsigned char candidate[MAX_LEN];
    
    for (uint32_t i = args->start; i < args->end && !g_found; i++) {
        if (args->cand_len == 2) {
            candidate[0] = (i >> 8) & 0xFF;
            candidate[1] = i & 0xFF;
        } else if (args->cand_len == 3) {
            candidate[0] = (i >> 16) & 0xFF;
            candidate[1] = (i >> 8) & 0xFF;
            candidate[2] = i & 0xFF;
        }
        
        check_candidate(candidate, args->cand_len, i, args);
        
        if ((i - args->start) % 2048 == 0 && i > args->start) {
            uint32_t done = i - args->start;
            uint32_t total = args->end - args->start;
            fprintf(stderr, "\rThread progress: %u/%u (%.1f%%)", done, total, 100.0*done/total);
        }
    }
    
    return NULL;
}

int main(int argc, char *argv[]) {
    int cand_len = 2;
    if (argc > 1) cand_len = atoi(argv[1]);
    if (cand_len < 1 || cand_len > 3) { fprintf(stderr, "Length 1-3\n"); return 1; }
    
    uint32_t total;
    if (cand_len == 1) total = 256;
    else if (cand_len == 2) total = 65536;
    else total = 16777216;
    
    printf("=== BrownOS Answer Hash Brute Force (C, fixed) ===\n");
    printf("Target:     %s\n", TARGET_HASH);
    printf("Iterations: %d\n", ITERATIONS);
    printf("Byte length: %d\n", cand_len);
    printf("Threads:    %d\n", NUM_THREADS);
    printf("Candidates: %u\n\n", total);
    fflush(stdout);
    
    pthread_t threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    
    uint32_t chunk_size = total / NUM_THREADS;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].start = i * chunk_size;
        args[i].end = (i + 1) * chunk_size;
        args[i].cand_len = cand_len;
        args[i].found = 0;
        if (i == NUM_THREADS - 1) args[i].end = total;
        pthread_create(&threads[i], NULL, brute_range, &args[i]);
    }
    
    int found = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (args[i].found) found = 1;
    }
    
    printf("\n=== RESULT ===\n");
    if (found)
        printf("MATCH FOUND!\n");
    else
        printf("No match for %d-byte candidates\n", cand_len);
    
    return found ? 0 : 1;
}
