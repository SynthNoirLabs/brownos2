/*
 * brute_brownos.c — Brute-force the BrownOS iterated SHA-1 answer
 *
 * Target: sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
 * Answer is CASE INSENSITIVE.
 *
 * Modes:
 *   Phase 1: Dictionary (built-in challenge-themed wordlist)
 *   Phase 2: Brute-force a-z, 1-5 chars (~12M, ~3hrs on M2 Max)
 *   Phase 3: Brute-force a-z0-9, 1-5 chars (~62M, ~14hrs on M2 Max)
 *
 * Build:  cc -O3 -o brute_brownos brute_brownos.c -lpthread
 *         (on macOS: uses CommonCrypto, no -lssl needed)
 *
 * Run:    ./brute_brownos            (all phases)
 *         ./brute_brownos dict       (dictionary only)
 *         ./brute_brownos brute      (brute-force only)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#define SHA1(d, n, md) CC_SHA1(d, (CC_LONG)(n), md)
#define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#else
#include <openssl/sha.h>
#define SHA_DIGEST_LENGTH 20
#endif

#define ITERATIONS 56154
#define NUM_THREADS 10

/* Target hash */
static const unsigned char TARGET[20] = {
    0x92, 0x52, 0xed, 0x65, 0xff, 0xac, 0x2a, 0xa7,
    0x63, 0xad, 0xb2, 0x1e, 0xf7, 0x2c, 0x01, 0x78,
    0xf1, 0xd8, 0x32, 0x86
};

static volatile int found = 0;
static char found_answer[256];

static int check_candidate(const char *candidate) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)candidate, strlen(candidate), hash);
    for (int i = 1; i < ITERATIONS; i++) {
        SHA1(hash, SHA_DIGEST_LENGTH, hash);
    }
    return memcmp(hash, TARGET, SHA_DIGEST_LENGTH) == 0;
}

/* ------------------------------------------------------------------ */
/* Dictionary                                                          */
/* ------------------------------------------------------------------ */

static const char *dictionary[] = {
    /* Lambda calculus terms */
    "lambda", "Lambda", "LAMBDA",
    "de bruijn", "De Bruijn", "debruijn", "DeBruijn", "de Bruijn",
    "debruijnindex", "de bruijn index",
    "church", "Church", "scott", "Scott",
    "cps", "CPS", "continuation",
    "beta", "Beta", "alpha", "eta",
    "reduction", "beta reduction", "beta-reduction",
    "combinator", "combinatory", "combinatory logic",
    "applicative", "normal form", "hnf", "whnf",
    "fixed point", "fixpoint", "Y combinator",
    "SKI", "ski", "BCKW", "bckw",
    
    /* BrownOS specific */
    "brownos", "BrownOS", "brown os", "Brown OS",
    "the brownos", "The BrownOS", "TheBrownOS",
    "brownos2", "ilikephp", "ILIKEPHP", "iLikePHP",
    "gizmore", "Gizmore", "GIZMORE",
    "dloser", "Dloser", "DLOSER",
    "GZKc.2/VQffio",
    "permission denied", "Permission denied", "Permission Denied",
    "not implemented", "Not implemented",
    "invalid argument", "Invalid argument",
    "not so fast", "Not so fast!",
    "oh, go choke on a towel!", "Oh, go choke on a towel!",
    "a towel", "towel", "choke",
    "wtf", "WTF", "Wtf",
    
    /* Filesystem data */
    "root", "mailer", "boss", "evil",
    "boss@evil.com", "mailer@brownos",
    "gizmore:ilikephp", "root:x",
    "/bin/sh", "/bin/false",
    "sudo", "su", "login",
    "sudo deluser dloser", "sodu deluser dloser",
    "passwd", "shadow", "etc/passwd",
    "access.log", "dloser@brownos",
    "00 FE FE", "00FEFE", "nil",
    "backdoor", "Backdoor", "BACKDOOR",
    "syscall", "syscall 201", "syscall 8",
    "sys8", "sys201", "sysC9",
    
    /* Bytecode/hex */
    "FD", "FE", "FF", "fd", "fe", "ff",
    "0xFF", "0xFD", "0xFE",
    "04C9FD08FDFF", "04c9fd08fdff",
    "00FEFEFF", "00fefeff",
    "FDFEFF", "fdfeff",
    
    /* Error messages */
    "Term too big!", "Encoding failed!", "Invalid term!",
    "Unexpected exception",
    "No such directory or file",
    "Not a directory", "Not a file",
    "Uhm... yeah... no...",
    
    /* Names/People */
    "Nicolaas Govert de Bruijn",
    "nicolaas govert de bruijn",
    "Alonzo Church", "alonzo church",
    "Haskell Curry", "haskell curry",
    "Alan Turing", "alan turing",
    "Christian", "christian",
    "space", "Space",
    "l3st3r", "L3st3r",
    "jusb3", "Jusb3",
    "pouniok",
    
    /* Common CTF answers */
    "flag", "Flag", "FLAG",
    "secret", "Secret", "SECRET",
    "answer", "Answer", "ANSWER",
    "solution", "Solution",
    "password", "Password",
    "admin", "root", "toor",
    "hack", "hacked", "pwned",
    "42", "1337", "31337",
    "true", "false", "True", "False",
    "yes", "no", "Yes", "No",
    "success", "win", "done",
    
    /* Math/CS */
    "turing", "Turing",
    "halting", "halting problem",
    "omega", "Omega",
    "K*", "K star", "kstar",
    "identity", "I combinator",
    "application", "abstraction",
    "postfix", "prefix", "infix",
    "eval", "apply", "reduce",
    "quine", "Quine",
    "self-application", "self application",
    
    /* Phrases from forum */
    "visit things", "investigate",
    "meaning of the input codes",
    "input codes", "the input codes",
    "don't be too literal",
    "core structures",
    "the geeks shall inherit the properties and methods of object earth",
    
    /* WeChall specific */
    "wechall", "WeChall", "WECHALL",
    "wc3.wechall.net",
    
    /* Single chars and digits */
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "a", "b", "c", "d", "e", "f",
    
    /* Numbers as strings */
    "201", "C9", "c9", "0xC9",
    "253", "254", "255", "256",
    "56154",
    "1000", "1002",
    "61221",
    
    /* Misc guesses */
    "left", "right", "Left", "Right",
    "pair", "Pair", "cons", "nil", "Nil", "NIL",
    "head", "tail",
    "encode", "decode",
    "quote", "unquote",
    "readdir", "readfile", "write", "echo",
    "crypt", "hash", "sha1", "SHA1",
    "capability", "token", "credential",
    "permission", "denied", "granted", "access",
    
    NULL
};

static void run_dictionary(void) {
    printf("[DICT] Running dictionary attack (%d words)...\n", 0);
    int count = 0;
    for (int i = 0; dictionary[i] != NULL; i++) count++;
    printf("[DICT] Running dictionary attack (%d words)...\n", count);
    
    time_t t0 = time(NULL);
    for (int i = 0; dictionary[i] != NULL && !found; i++) {
        if (check_candidate(dictionary[i])) {
            found = 1;
            strncpy(found_answer, dictionary[i], sizeof(found_answer) - 1);
            printf("\n*** FOUND! Answer: \"%s\" ***\n", dictionary[i]);
            return;
        }
        if ((i + 1) % 50 == 0) {
            printf("[DICT] %d/%d checked...\r", i + 1, count);
            fflush(stdout);
        }
    }
    time_t t1 = time(NULL);
    printf("[DICT] Done. %d words checked in %lds. No match.\n", count, t1 - t0);
}

/* ------------------------------------------------------------------ */
/* Brute-force                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    int thread_id;
    const char *charset;
    int charset_len;
    int max_len;
    long long total;
    long long checked;
} brute_args_t;

static long long total_checked = 0;
static pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t brute_start_time;
static long long brute_total_candidates;

static void brute_recurse(char *buf, int pos, int max_len,
                          const char *charset, int charset_len,
                          long long *local_checked) {
    if (found) return;
    
    if (pos > 0) {
        buf[pos] = '\0';
        if (check_candidate(buf)) {
            found = 1;
            strncpy(found_answer, buf, sizeof(found_answer) - 1);
            printf("\n*** FOUND! Answer: \"%s\" ***\n", buf);
            return;
        }
        (*local_checked)++;
        
        if ((*local_checked) % 100 == 0) {
            pthread_mutex_lock(&counter_lock);
            total_checked += 100;
            long long tc = total_checked;
            pthread_mutex_unlock(&counter_lock);
            
            if (tc % 5000 == 0) {
                time_t now = time(NULL);
                double elapsed = difftime(now, brute_start_time);
                double rate = elapsed > 0 ? tc / elapsed : 0;
                double remaining = rate > 0 ? (brute_total_candidates - tc) / rate : 0;
                int rh = (int)(remaining / 3600);
                int rm = (int)((remaining - rh * 3600) / 60);
                printf("[BRUTE] %lld / %lld (%.1f/s) ETA: %dh%02dm    \r",
                       tc, brute_total_candidates, rate, rh, rm);
                fflush(stdout);
            }
        }
    }
    
    if (pos >= max_len) return;
    
    for (int i = 0; i < charset_len && !found; i++) {
        buf[pos] = charset[i];
        brute_recurse(buf, pos + 1, max_len, charset, charset_len, local_checked);
    }
}

static void *brute_thread(void *arg) {
    brute_args_t *a = (brute_args_t *)arg;
    char buf[64];
    long long local_checked = 0;
    
    /* Each thread handles a subset of first characters */
    int chars_per_thread = (a->charset_len + NUM_THREADS - 1) / NUM_THREADS;
    int start = a->thread_id * chars_per_thread;
    int end = start + chars_per_thread;
    if (end > a->charset_len) end = a->charset_len;
    
    for (int i = start; i < end && !found; i++) {
        /* Single char */
        buf[0] = a->charset[i];
        buf[1] = '\0';
        if (check_candidate(buf)) {
            found = 1;
            strncpy(found_answer, buf, sizeof(found_answer) - 1);
            printf("\n*** FOUND! Answer: \"%s\" ***\n", buf);
            return NULL;
        }
        local_checked++;
        
        /* Multi char: this char as prefix */
        for (int len = 2; len <= a->max_len && !found; len++) {
            brute_recurse(buf, 1, len, a->charset, a->charset_len, &local_checked);
        }
    }
    
    pthread_mutex_lock(&counter_lock);
    total_checked += (local_checked % 100); /* flush remainder */
    pthread_mutex_unlock(&counter_lock);
    
    return NULL;
}

static long long calc_total(int charset_len, int max_len) {
    long long total = 0;
    long long power = 1;
    for (int i = 1; i <= max_len; i++) {
        power *= charset_len;
        total += power;
    }
    return total;
}

static void run_brute(const char *charset, int max_len, const char *label) {
    int charset_len = (int)strlen(charset);
    brute_total_candidates = calc_total(charset_len, max_len);
    total_checked = 0;
    brute_start_time = time(NULL);
    
    printf("[BRUTE] %s: %lld candidates, %d threads, max_len=%d\n",
           label, brute_total_candidates, NUM_THREADS, max_len);
    
    pthread_t threads[NUM_THREADS];
    brute_args_t args[NUM_THREADS];
    
    for (int t = 0; t < NUM_THREADS; t++) {
        args[t].thread_id = t;
        args[t].charset = charset;
        args[t].charset_len = charset_len;
        args[t].max_len = max_len;
        args[t].total = brute_total_candidates;
        args[t].checked = 0;
        pthread_create(&threads[t], NULL, brute_thread, &args[t]);
    }
    
    for (int t = 0; t < NUM_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }
    
    time_t elapsed = time(NULL) - brute_start_time;
    if (!found) {
        printf("[BRUTE] %s: Done. %lld checked in %lds. No match.\n",
               label, brute_total_candidates, elapsed);
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    int do_dict = 1, do_brute = 1;
    
    if (argc > 1) {
        if (strcmp(argv[1], "dict") == 0) do_brute = 0;
        else if (strcmp(argv[1], "brute") == 0) do_dict = 0;
    }
    
    printf("=== BrownOS Brute-Force ===\n");
    printf("Target: 9252ed65ffac2aa763adb21ef72c0178f1d83286\n");
    printf("Iterations: %d × SHA-1\n", ITERATIONS);
    printf("Threads: %d\n\n", NUM_THREADS);
    
    if (do_dict && !found) {
        run_dictionary();
    }
    
    if (do_brute && !found) {
        printf("\n");
        run_brute("abcdefghijklmnopqrstuvwxyz", 5, "a-z 1-5 chars");
    }
    
    if (do_brute && !found) {
        printf("\n");
        run_brute("abcdefghijklmnopqrstuvwxyz0123456789", 5, "a-z0-9 1-5 chars");
    }
    
    if (found) {
        printf("\n============================================\n");
        printf("ANSWER FOUND: \"%s\"\n", found_answer);
        printf("============================================\n");
    } else {
        printf("\nNo answer found in searched space.\n");
    }
    
    return found ? 0 : 1;
}
