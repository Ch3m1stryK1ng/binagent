// vuln2.c - intentionally vulnerable toy program for static analysis testing
// DO NOT use in production.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void die(const char *msg) {
    puts(msg);
    exit(1);
}

// Vulnerability A: stack overflow + format string
static void handle_line(const char *line) {
    char buf[64];

    // A1: classic stack overflow
    strcpy(buf, line);

    // A2: format string (user-controlled)
    printf(buf);

    puts("");
}

// Vulnerability B: integer overflow -> undersized allocation -> heap overflow
static void parse_blob(const unsigned char *p, size_t n) {
    // Expect header: [u32 count][count bytes payload]
    if (n < 4) return;

    uint32_t count = 0;
    memcpy(&count, p, 4);

    // B1: integer overflow when count is huge -> alloc smaller than expected
    size_t alloc_sz = (size_t)count + 16;

    unsigned char *heap = (unsigned char *)malloc(alloc_sz);
    if (!heap) return;

    // B2: heap overflow: copies count bytes into alloc_sz buffer (alloc_sz may wrap)
    // also even without wrap, count may exceed remaining n
    memcpy(heap, p + 4, (size_t)count);

    // use heap a bit
    if (alloc_sz > 0) heap[0] ^= 0xAA;

    free(heap);
}

// Vulnerability C: use-after-free
static void uaf_demo(const char *s) {
    char *p = (char *)malloc(32);
    if (!p) return;
    strncpy(p, s, 31);
    p[31] = '\0';

    free(p);

    // C1: use-after-free
    if (p[0] == 'A') {
        puts("starts with A");
    }
}

// Vulnerability D: unsafe path construction (classic overflow pattern)
static void build_path(const char *name) {
    char path[64] = "/tmp/";
    // D1: strcat without bounds
    strcat(path, name);

    // Just a harmless use
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        puts("opened");
    } else {
        puts("not opened");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("usage: vuln2 <mode> [arg]");
        puts("modes: line <text> | blob <hex> | uaf <text> | path <name>");
        return 0;
    }

    if (strcmp(argv[1], "line") == 0) {
        const char *in = (argc >= 3) ? argv[2] : "";
        handle_line(in);
        return 0;
    }

    if (strcmp(argv[1], "uaf") == 0) {
        const char *in = (argc >= 3) ? argv[2] : "A";
        uaf_demo(in);
        return 0;
    }

    if (strcmp(argv[1], "path") == 0) {
        const char *in = (argc >= 3) ? argv[2] : "x";
        build_path(in);
        return 0;
    }

    if (strcmp(argv[1], "blob") == 0) {
        // simple hex decoder: argv[2] is hex bytes (e.g., "01020304...")
        const char *hex = (argc >= 3) ? argv[2] : "";
        size_t hl = strlen(hex);
        if (hl % 2 != 0) die("hex length must be even");
        size_t out_n = hl / 2;

        unsigned char *buf = (unsigned char *)malloc(out_n);
        if (!buf) die("oom");

        for (size_t i = 0; i < out_n; i++) {
            unsigned int x = 0;
            if (sscanf(hex + i * 2, "%2x", &x) != 1) die("bad hex");
            buf[i] = (unsigned char)x;
        }

        parse_blob(buf, out_n);
        free(buf);
        return 0;
    }

    puts("unknown mode");
    return 0;
}
