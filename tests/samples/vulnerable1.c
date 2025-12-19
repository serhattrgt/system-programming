#include <stdio.h>
#include <string.h>

void func() {
    char buffer[10];
    gets(buffer); 
    
    char dest[10];
    char *src = "very long string";
    strcpy(dest, src); 
    
    char big[100];
    sprintf(big, "%s", src); 
    
    strcat(dest, src); 

}
