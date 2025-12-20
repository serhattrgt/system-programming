#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe_function() {
    char buffer[100];
    

    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
    }

    char dest[50];
    const char *src = "Safe string copy";
    
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';

    char formatted[100];
    snprintf(formatted, sizeof(formatted), "Formatted: %s", dest);

    strncat(dest, " appended", sizeof(dest) - strlen(dest) - 1);
    
    printf("%s\n", formatted);
    
    size_t count = 10;
    size_t size = sizeof(int);
    if (count < SIZE_MAX / size) {
        int *arr = malloc(count * size);
        if (arr) free(arr);
    }
}

int main() {
    safe_function();
    return 0;
}
