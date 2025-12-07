#include <stdio.h>
#include <string.h>
#include "recommender.h"

void get_recommendation(const char *func, const char *type, const char **reason, const char **suggestion, const char **example) {
    if (strcmp(func, "gets") == 0) {
        *reason = "gets() does not check the length of the input, which can easily cause buffer overflows. It can lead to crashes, data corruption, or serious security vulnerabilities. This function was removed from the C11 standard because it is unsafe.";
        *suggestion = "Use fgets() instead of gets().";
        *example = "    // Unsafe:\n    gets(buffer);\n    // Safe:\n    fgets(buffer, sizeof(buffer), stdin);\n    buffer[strcspn(buffer, \"\\n\")] = 0; // remove newline";
    } else if (strcmp(func, "strcpy") == 0) {
        *reason = "strcpy() does not check the destination buffer size. If the source string is longer than the destination, it will cause a buffer overflow, leading to crashes, data corruption, or security vulnerabilities.";
        *suggestion = "Use strncpy() instead of strcpy() (ensure null termination).";
        *example = "    // Unsafe:\n    strcpy(dest, src);\n    // Safe:\n    strncpy(dest, src, sizeof(dest) - 1);\n    dest[sizeof(dest) - 1] = '\\0';";
    } else if (strcmp(func, "strcat") == 0) {
        *reason = "strcat() does not check if the destination has enough space for the appended string.";
        *suggestion = "Use strncat().";
        *example = "    // Safe:\n    strncat(dest, src, sizeof(dest) - strlen(dest) - 1);";
    } else if (strcmp(func, "sprintf") == 0) {
        *reason = "sprintf() does not check the destination buffer size.";
        *suggestion = "Use snprintf().";
        *example = "    // Safe:\n    snprintf(buf, sizeof(buf), \"%s\", src);";
    } else if (strcmp(func, "scanf") == 0) {
        *reason = "scanf() with %s can cause buffer overflow if input exceeds buffer size.";
        *suggestion = "Use width specifier (e.g. %99s).";
        *example = "    // Safe:\n    scanf(\"%99s\", buf);";
    } else if (strcmp(type, "Command Injection") == 0) {
        *reason = "Using system() or popen() with user-controlled input can lead to command injection.";
        *suggestion = "Avoid system() if possible. Use execve() family functions which separates arguments.";
        *example = "    // Safe:\n    char *args[] = {\"/bin/ls\", \"-l\", NULL};\n    execve(\"/bin/ls\", args, NULL);";
    } else if (strcmp(type, "Format String Vulnerability") == 0) {
        *reason = "Passing a variable directly as format string (e.g. printf(str)) allows attackers to read/write stack memory.";
        *suggestion = "Always use a format string literal.";
        *example = "    // Unsafe:\n    printf(user_input);\n    // Safe:\n    printf(\"%s\", user_input);";
    } else if (strcmp(type, "Integer Overflow Risk") == 0) {
        *reason = "malloc(A * B) can overflow if A*B is too large, resulting in a small allocation and subsequent heap overflow.";
        *suggestion = "Check for overflow before multiplication.";
        *example = "    // Safe:\n    if (count > SIZE_MAX / size) return NULL;\n    void *ptr = malloc(count * size);";
    } else if (strcmp(type, "Thread-Unsafe Time Function") == 0) {
        *reason = "This function returns a pointer to a static buffer, which is not thread-safe.";
        *suggestion = "Use the reentrant version (e.g. localtime_r).";
        *example = "    // Safe:\n    localtime_r(&timer, &result);";
    } else {
        *reason = "This function involves potential security risks.";
        *suggestion = "Use a safer alternative.";
        *example = "";
    }
}

void print_scan_report(const char *filename, Vulnerability *head) {
    int count = 0;
    Vulnerability *curr = head;
    while (curr) {
        printf("Line %d: %s() used", curr->line, curr->function_name);
        if (strcmp(curr->issue_type, "Unsafe Function") != 0 && strcmp(curr->issue_type, "Thread-Unsafe Time Function") != 0) {
             printf(" (%s)", curr->issue_type);
        }
        printf("\n");
        count++;
        curr = curr->next;
    }
    printf("\nTotal %d security issues found.\n", count);
}

void print_recommendation_report(const char *filename, Vulnerability *head) {
    Vulnerability *curr = head;
    while (curr) {
        printf("Line %d: %s() used\n", curr->line, curr->function_name);
        
        const char *reason, *suggestion, *example;
        get_recommendation(curr->function_name, curr->issue_type, &reason, &suggestion, &example);
        
        printf("%s\n\n", reason);
        printf("Suggestion: %s\n", suggestion);
        if (strlen(example) > 0) {
             printf("  Example:\n%s\n", example);
        }
        printf("\n");
        curr = curr->next;
    }
}
