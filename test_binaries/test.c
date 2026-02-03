#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf(buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable(argv[1]);
    }
    printf("Hello from test binary!\n");
    return 0;
}
