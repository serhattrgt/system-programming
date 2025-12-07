#include <stdio.h>
#include <string.h>

void func() {
    char buffer[10];
    gets(buffer); // Unsafe
    
    char dest[10];
    char *src = "very long string";
    strcpy(dest, src); // Unsafe
    
    char big[100];
    sprintf(big, "%s", src); // Unsafe
    
    strcat(dest, src); // Unsafe
}
