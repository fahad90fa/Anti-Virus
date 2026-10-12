/*
 * benign_hello.c — a harmless test program for verifying the execute gate.
 *
 * This does nothing but print a line and exit. It is NOT malware. The VM
 * integration harness builds it, adds ITS OWN hash to a temporary test
 * blocklist, and then confirms the Sentinel minifilter blocks it from executing
 * — proving the real-time execute gate works using an entirely benign binary
 * (no malicious sample needed, the same principle as EICAR for the scanner).
 *
 * Build:  cl /W4 benign_hello.c
 */
#include <stdio.h>

int main(void) {
    printf("benign_hello: if you can read this, I was allowed to run.\n");
    return 0;
}
