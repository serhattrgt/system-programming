#include <stdio.h>
#include <stdlib.h>

void ext_func(char *input) {
    printf(input); // Format string
    fprintf(stderr, input); // Format string
    
    system("ls -la"); // Command injection
    popen("cat file", "r"); // Command injection
    
    int count = 100;
    int size = 50;
    void *ptr = malloc(count * size); // Overflow
}
