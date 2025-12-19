#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void safe_function() {
    char buffer[100];
    
    // safe alternative to reading lines
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Remove newline if present
        buffer[strcspn(buffer, "\n")] = 0;
    }

    char dest[50];
    const char *src = "Safe string copy";
    
    // Safe string copy ensuring null termination
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';

    // Safe formatting with size limit
    char formatted[100];
    snprintf(formatted, sizeof(formatted), "Formatted: %s", dest);

    // Safe concatenation
    strncat(dest, " appended", sizeof(dest) - strlen(dest) - 1);
    
    // Safe print with format string literal
    printf("%s\n", formatted);
    
    // Safe use of malloc with overflow check
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
