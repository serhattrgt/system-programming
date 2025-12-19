#include <stdio.h>
#include <stdlib.h>

void ext_func(char *input) {
    printf(input); 
    fprintf(stderr, input); 
    
    system("ls -la"); 
    popen("cat file", "r"); 
    
    int count = 100;
    int size = 50;
    void *ptr = malloc(count * size); 
}
