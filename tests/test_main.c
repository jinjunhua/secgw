/*
 * Combined test runner main entry point
 */
#include <stdio.h>

/* Declarations for individual test suites */
int run_sm3_tests(void);
int run_sm4_tests(void);
int run_sm2_tests(void);
int run_ipsec_tests(void);

int main(void)
{
    int ok = 1;
    printf("==================================================\n");
    printf(" GM IPSec - Full Test Suite\n");
    printf("==================================================\n\n");
    printf("=== SM3 Tests ===\n");
    ok &= run_sm3_tests();
    printf("\n=== SM4 Tests ===\n");
    ok &= run_sm4_tests();
    printf("\n=== SM2 Tests ===\n");
    ok &= run_sm2_tests();
    printf("\n=== IPSec Tests ===\n");
    ok &= run_ipsec_tests();
    printf("\n==================================================\n");
    printf(" Overall: %s\n", ok ? "ALL PASSED" : "SOME FAILED");
    printf("==================================================\n");
    return ok ? 0 : 1;
}
