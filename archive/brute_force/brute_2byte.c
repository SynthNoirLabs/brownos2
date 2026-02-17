#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>

#define TARGET_HASH "9252ed65ffac2aa763adb21ef72c0178f1d83286"
#define ITERATIONS 56154
#define NUM_THREADS 16

typedef struct {
    uint32_t start;
    uint32_t end;
    int found;
    uint16_t match_value;
} thread_args_t;

void sha1_56154(unsigned char *data, int len, char *result) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char hex_str[SHA_DIGEST_LENGTH * 2 + 1];
    unsigned char temp[SHA_DIGEST_LENGTH * 2];
    
    memcpy(hash, data, len);
    int hash_len = len;
    
    for (int i = 0; i < ITERATIONS; i++) {
        SHA1(hash, hash_len, hash);
        
        // Convert to hex string
        for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
            sprintf((char*)hex_str + j*2, "%02x", hash[j]);
        }
        hash_len = SHA_DIGEST_LENGTH * 2;
        memcpy(temp, hex_str, hash_len);
        memcpy(hash, temp, SHA_DIGEST_LENGTH);
    }
    
    // Final result is the hex string
    memcpy(result, hex_str, SHA_DIGEST_LENGTH * 2);
    result[SHA_DIGEST_LENGTH * 2] = '\0';
}

void* brute_range(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    unsigned char candidate[2];
    char hash_result[SHA_DIGEST_LENGTH * 2 + 1];
    
    for (uint32_t i = args->start; i < args->end; i++) {
        candidate[0] = (i >> 8) & 0xFF;
        candidate[1] = i & 0xFF;
        
        sha1_56154(candidate, 2, hash_result);
        
        if (strcmp(hash_result, TARGET_HASH) == 0) {
            printf("\n✓✓✓ MATCH FOUND: 0x%04X (%02X%02X) ✓✓✓\n", 
                   i, candidate[0], candidate[1]);
            args->found = 1;
            args->match_value = i;
            return NULL;
        }
        
        // Progress every 4096 values
        if ((i - args->start) % 4096 == 0 && i > args->start) {
            printf("Thread %lu: %u/%u\n", (unsigned long)(args - (thread_args_t*)NULL), 
                   i - args->start, args->end - args->start);
            fflush(stdout);
        }
    }
    
    return NULL;
}

int main() {
    printf("=== BrownOS Answer Hash Brute Force (C) ===\n");
    printf("Target:     %s\n", TARGET_HASH);
    printf("Iterations: %d\n", ITERATIONS);
    printf("Str length: 2 bytes\n");
    printf("Threads:    %d\n", NUM_THREADS);
    printf("Candidates: 65536\n\n");
    
    pthread_t threads[NUM_THREADS];
    thread_args_t args[NUM_THREADS];
    
    uint32_t chunk_size = 65536 / NUM_THREADS;
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].start = i * chunk_size;
        args[i].end = (i + 1) * chunk_size;
        args[i].found = 0;
        if (i == NUM_THREADS - 1) {
            args[i].end = 65536;  // Ensure last thread covers remainder
        }
        pthread_create(&threads[i], NULL, brute_range, &args[i]);
    }
    
    // Wait for threads
    int found = 0;
    uint16_t match_value = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (args[i].found) {
            found = 1;
            match_value = args[i].match_value;
        }
    }
    
    printf("\n=== RESULT ===\n");
    if (found) {
        printf("✓ MATCH FOUND: 0x%04X\n", match_value);
    } else {
        printf("✗ No matches found\n");
    }
    
    return found ? 0 : 1;
}
