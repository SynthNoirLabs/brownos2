/*
 * brute4.c - BrownOS answer hash brute-force (4/5/6 char printable ASCII)
 *
 * Hash verification: sha1^56154(candidate) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
 * Each SHA1 iteration operates on the 40-char lowercase hex digest string.
 *
 * Compile: gcc -O3 -o brute4 brute4.c -lssl -lcrypto -lpthread
 * Run:     ./brute4 4 16     (4-char strings, 16 threads)
 *          ./brute4 5 16     (5-char strings, 16 threads)
 *          ./brute4 6 16     (6-char strings, 16 threads)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/sha.h>

#define ITERATIONS 56154
#define TARGET "9252ed65ffac2aa763adb21ef72c0178f1d83286"
#define CHARSET_START 32   /* space */
#define CHARSET_END 126    /* tilde */
#define CHARSET_SIZE (CHARSET_END - CHARSET_START + 1)  /* 95 */

static const char hex_chars[] = "0123456789abcdef";
static volatile int found = 0;

/* Compute SHA1 and write lowercase hex digest to output (must be >=41 bytes) */
static inline void sha1_hex(const char *input, int input_len, char *output) {
    unsigned char hash[20];
    SHA1((const unsigned char *)input, input_len, hash);
    for (int i = 0; i < 20; i++) {
        output[i * 2]     = hex_chars[hash[i] >> 4];
        output[i * 2 + 1] = hex_chars[hash[i] & 0x0f];
    }
    output[40] = '\0';
}

/* Run the full sha1^56154 chain and compare to TARGET */
static int check_candidate(const char *candidate, int len) {
    char buf[41];
    /* First iteration: SHA1 of the raw candidate string */
    sha1_hex(candidate, len, buf);
    /* Remaining 56153 iterations: SHA1 of the 40-char hex digest */
    for (int i = 1; i < ITERATIONS; i++) {
        sha1_hex(buf, 40, buf);
    }
    return memcmp(buf, TARGET, 40) == 0;
}

typedef struct {
    int start_char;   /* first char value for position 0 (inclusive) */
    int end_char;     /* last char value for position 0 (exclusive) */
    int str_len;      /* candidate string length (4, 5, or 6) */
    int thread_id;
} thread_arg_t;

static void *worker(void *arg) {
    thread_arg_t *ta = (thread_arg_t *)arg;
    char candidate[7];
    int len = ta->str_len;
    long long count = 0;

    memset(candidate, 0, sizeof(candidate));

    for (int a = ta->start_char; a < ta->end_char && !found; a++) {
        candidate[0] = (char)a;
        for (int b = CHARSET_START; b <= CHARSET_END && !found; b++) {
            candidate[1] = (char)b;

            if (len == 4) {
                for (int c = CHARSET_START; c <= CHARSET_END && !found; c++) {
                    candidate[2] = (char)c;
                    for (int d = CHARSET_START; d <= CHARSET_END && !found; d++) {
                        candidate[3] = (char)d;
                        candidate[4] = '\0';
                        if (check_candidate(candidate, 4)) {
                            printf("\n*** MATCH FOUND: \"%s\" ***\n", candidate);
                            printf("Hex: ");
                            for (int i = 0; i < 4; i++)
                                printf("%02x", (unsigned char)candidate[i]);
                            printf("\n");
                            found = 1;
                            return NULL;
                        }
                        count++;
                    }
                }
            } else if (len == 5) {
                for (int c = CHARSET_START; c <= CHARSET_END && !found; c++) {
                    candidate[2] = (char)c;
                    for (int d = CHARSET_START; d <= CHARSET_END && !found; d++) {
                        candidate[3] = (char)d;
                        for (int e = CHARSET_START; e <= CHARSET_END && !found; e++) {
                            candidate[4] = (char)e;
                            candidate[5] = '\0';
                            if (check_candidate(candidate, 5)) {
                                printf("\n*** MATCH FOUND: \"%s\" ***\n", candidate);
                                printf("Hex: ");
                                for (int i = 0; i < 5; i++)
                                    printf("%02x", (unsigned char)candidate[i]);
                                printf("\n");
                                found = 1;
                                return NULL;
                            }
                            count++;
                        }
                    }
                }
            } else if (len == 6) {
                for (int c = CHARSET_START; c <= CHARSET_END && !found; c++) {
                    candidate[2] = (char)c;
                    for (int d = CHARSET_START; d <= CHARSET_END && !found; d++) {
                        candidate[3] = (char)d;
                        for (int e = CHARSET_START; e <= CHARSET_END && !found; e++) {
                            candidate[4] = (char)e;
                            for (int f = CHARSET_START; f <= CHARSET_END && !found; f++) {
                                candidate[5] = (char)f;
                                candidate[6] = '\0';
                                if (check_candidate(candidate, 6)) {
                                    printf("\n*** MATCH FOUND: \"%s\" ***\n", candidate);
                                    printf("Hex: ");
                                    for (int i = 0; i < 6; i++)
                                        printf("%02x", (unsigned char)candidate[i]);
                                    printf("\n");
                                    found = 1;
                                    return NULL;
                                }
                                count++;
                            }
                        }
                    }
                }
            }
        }
        printf("[T%02d] char %d ('%c') done, tested %lld so far\n",
               ta->thread_id, a, (char)a, count);
        fflush(stdout);
    }
    printf("[T%02d] finished, tested %lld candidates\n", ta->thread_id, count);
    fflush(stdout);
    return NULL;
}

int main(int argc, char *argv[]) {
    int num_threads = 16;
    int str_len = 4;

    if (argc > 1) str_len = atoi(argv[1]);
    if (argc > 2) num_threads = atoi(argv[2]);

    if (str_len < 4 || str_len > 6) {
        fprintf(stderr, "String length must be 4, 5, or 6\n");
        return 2;
    }
    if (num_threads < 1 || num_threads > 128) {
        fprintf(stderr, "Thread count must be 1-128\n");
        return 2;
    }

    long long total = 1;
    for (int i = 0; i < str_len; i++) total *= CHARSET_SIZE;

    printf("=== BrownOS Answer Hash Brute Force (C) ===\n");
    printf("Target:     %s\n", TARGET);
    printf("Iterations: %d\n", ITERATIONS);
    printf("Str length: %d\n", str_len);
    printf("Threads:    %d\n", num_threads);
    printf("Charset:    %d-%d (%d printable ASCII chars)\n",
           CHARSET_START, CHARSET_END, CHARSET_SIZE);
    printf("Candidates: %lld\n\n", total);
    fflush(stdout);

    time_t start = time(NULL);

    pthread_t threads[num_threads];
    thread_arg_t args[num_threads];

    int chars_per_thread = CHARSET_SIZE / num_threads;
    int remainder = CHARSET_SIZE % num_threads;
    int current = CHARSET_START;

    for (int i = 0; i < num_threads; i++) {
        args[i].start_char = current;
        args[i].end_char = current + chars_per_thread + (i < remainder ? 1 : 0);
        args[i].str_len = str_len;
        args[i].thread_id = i;
        current = args[i].end_char;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    time_t elapsed = time(NULL) - start;
    printf("\nElapsed: %ld seconds\n", (long)elapsed);

    if (!found) {
        printf("NO MATCH for %d-char printable ASCII strings\n", str_len);
    }

    return found ? 0 : 1;
}
