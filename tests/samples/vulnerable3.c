#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_input() {
    char user_input[20];
    int count;
    int size;

    printf("Enter username: ");
    scanf("%s", user_input); 

    char dest[10] = "Hello";
    
    char *src = " World! This is too long";

    strncat(dest, src, sizeof(dest)); 

    printf("Enter count and size: ");
    if (scanf("%d %d", &count, &size) == 2) {

        char *buffer = (char *)malloc(count * size);
        if (buffer) {

            free(buffer);
        }
    }
}
