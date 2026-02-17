#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define TARGET_HASH "9252ed65ffac2aa763adb21ef72c0178f1d83286"
#define ITERATIONS 56154

int main() {
    printf("=== BrownOS 2-Byte Brute Force ===\n");
    printf("Target: %s\n", TARGET_HASH);
    printf("Iterations: %d\n\n", ITERATIONS);
    
    unsigned char candidate[2];
    unsigned char hash[SHA_DIGEST_LENGTH];
    char hex_result[SHA_DIGEST_LENGTH * 2 + 1];
    
    for (int i = 0; i < 65536; i++) {
        candidate[0] = (i >> 8) & 0xFF;
        candidate[1] = i & 0xFF;
        
        // Initial hash
        SHA1(candidate, 2, hash);
        
        // Iterate 56153 more times
        for (int j = 1; j < ITERATIONS; j++) {
            // Convert current hash to hex string
            for (int k = 0; k < SHA_DIGEST_LENGTH; k++) {
                sprintf(hex_result + k*2, "%02x", hash[k]);
            }
            // Hash the hex string
            SHA1((unsigned char*)hex_result, SHA_DIGEST_LENGTH * 2, hash);
        }
        
        // Convert final hash to hex
        for (int k = 0; k < SHA_DIGEST_LENGTH; k++) {
            sprintf(hex_result + k*2, "%02x", hash[k]);
        }
        hex_result[SHA_DIGEST_LENGTH * 2] = '\0';
        
        if (strcmp(hex_result, TARGET_HASH) == 0) {
            printf("\n✓✓✓ MATCH FOUND: 0x%04X (%02X%02X) ✓✓✓\n", 
                   i, candidate[0], candidate[1]);
            return 0;
        }
        
        // Progress every 4096
        if ((i + 1) % 4096 == 0) {
            printf("Progress: %d/65536 (%.1f%%)\n", i+1, 100.0*(i+1)/65536);
            fflush(stdout);
        }
    }
    
    printf("\n✗ No matches found\n");
    return 1;
}
