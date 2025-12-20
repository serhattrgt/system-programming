#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "recommender.h"

void get_recommendation(const char *func, const char *type, const char **reason, const char **suggestion, const char **example) {
    if (strcmp(func, "gets") == 0) {
        *reason = "gets() does not check the length of the input, which can easily cause buffer overflows. It can lead to crashes, data corruption, or serious security vulnerabilities. This function was removed from the C11 standard because it is unsafe.";
        *suggestion = "Use fgets() instead of gets().";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    gets(buffer);\n    \033[1;32m// Safe:\033[0m\n    fgets(buffer, sizeof(buffer), stdin);\n    buffer[strcspn(buffer, \"\\n\")] = 0; // remove newline";
    } else if (strcmp(func, "strcpy") == 0) {
        *reason = "strcpy() does not check the destination buffer size. If the source string is longer than the destination, it will cause a buffer overflow, leading to crashes, data corruption, or security vulnerabilities.";
        *suggestion = "Use strncpy() instead of strcpy() (ensure null termination).";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    strcpy(dest, src);\n    \033[1;32m// Safe:\033[0m\n    strncpy(dest, src, sizeof(dest) - 1);\n    dest[sizeof(dest) - 1] = '\\0';";
    } else if (strcmp(func, "strcat") == 0) {
        *reason = "strcat() does not check if the destination has enough space for the appended string.";
        *suggestion = "Use strncat().";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    strcat(dest, src);\n    \033[1;32m// Safe:\033[0m\n    strncat(dest, src, sizeof(dest) - strlen(dest) - 1);";
    } else if (strcmp(func, "sprintf") == 0) {
        *reason = "sprintf() does not check the destination buffer size.";
        *suggestion = "Use snprintf().";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    sprintf(buf, \"%s\", src);\n    \033[1;32m// Safe:\033[0m\n    snprintf(buf, sizeof(buf), \"%s\", src);";
    } else if (strcmp(func, "scanf") == 0) {
        *reason = "scanf() with %s can cause buffer overflow if input exceeds buffer size.";
        *suggestion = "Use width specifier (e.g. %99s).";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    scanf(\"%s\", buf);\n    \033[1;32m// Safe:\033[0m\n    scanf(\"%99s\", buf);";
    } else if (strcmp(type, "Command Injection") == 0) {
        *reason = "Using system() or popen() with user-controlled input can lead to command injection.";
        *suggestion = "Avoid system() if possible. Use execve() family functions which separates arguments.";
        
        if (strcmp(func, "system") == 0) {
             *example = "    \033[1;31m// Unsafe:\033[0m\n    system(command);\n    \033[1;32m// Safe:\033[0m\n    // Use fork() + execve()\n    char *args[] = {\"/bin/ls\", \"-l\", NULL};\n    execve(\"/bin/ls\", args, NULL);";
        } else if (strcmp(func, "popen") == 0) {
             *example = "    \033[1;31m// Unsafe:\033[0m\n    popen(cmd, \"r\");\n    \033[1;32m// Safe:\033[0m\n    // Use fork() + execve()\n    char *args[] = {\"/bin/ls\", \"-l\", NULL};\n    execve(\"/bin/ls\", args, NULL);";
        } else {
             *example = "    \033[1;31m// Unsafe:\033[0m\n    system(command);\n    \033[1;32m// Safe:\033[0m\n    execve(...);";
        }

    } else if (strcmp(type, "Format String Vulnerability") == 0) {
        *reason = "Passing a variable directly as format string (e.g. printf(str)) allows attackers to read/write stack memory.";
        *suggestion = "Always use a format string literal.";
        
        if (strcmp(func, "printf") == 0) {
            *example = "    \033[1;31m// Unsafe:\033[0m\n    printf(user_input);\n    \033[1;32m// Safe:\033[0m\n    printf(\"%s\", user_input);";
        } else if (strcmp(func, "fprintf") == 0) {
            *example = "    \033[1;31m// Unsafe:\033[0m\n    fprintf(fp, user_input);\n    \033[1;32m// Safe:\033[0m\n    fprintf(fp, \"%s\", user_input);";
        } else {
             *example = "    \033[1;31m// Unsafe:\033[0m\n    printf(user_input);\n    \033[1;32m// Safe:\033[0m\n    printf(\"%s\", user_input);";
        }

    } else if (strcmp(type, "Integer Overflow Risk") == 0) {
        *reason = "malloc(A * B) can overflow if A*B is too large, resulting in a small allocation and subsequent heap overflow.";
        *suggestion = "Check for overflow before multiplication.";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    void *ptr = malloc(count * size);\n    \033[1;32m// Safe:\033[0m\n    if (count > SIZE_MAX / size) return NULL;\n    void *ptr = malloc(count * size);";
    } else if (strcmp(type, "Thread-Unsafe Time Function") == 0) {
        *reason = "This function returns a pointer to a static buffer, which is not thread-safe.";
        *suggestion = "Use the reentrant version (e.g. localtime_r).";
        *example = "    \033[1;31m// Unsafe:\033[0m\n    localtime(&timer);\n    \033[1;32m// Safe:\033[0m\n    localtime_r(&timer, &result);";
    } else {
        *reason = "This function involves potential security risks.";
        *suggestion = "Use a safer alternative.";
        *example = "";
    }
}

// Helper to print wrapped text with a prefix per line
void print_wrapped(const char *text, int width, const char *prefix) {
    const char *start = text;
    while (*start) {
        const char *end = start;
        int len = 0;
        
        // Find split point
        while (*end && len < width) {
            len++;
            end++;
        }
        
        // Backtrack to safe space if not at end
        if (*end) {
            while (end > start && *end != ' ') {
                end--;
            }
            if (end == start) { // No space found, force split
                end = start + width;
            }
        }
        
        printf("%s%.*s\n", prefix, (int)(end - start), start);
        
        start = end;
        while (*start == ' ') start++;
    }
}

void print_scan_report(const char *filename, Vulnerability *head, int verbose) {
    if (!head) {
        printf("\n\033[1;32m ✔ \033[0m No vulnerabilities found in \033[1m%s\033[0m.\n", filename);
        return;
    }
    
    printf("\n \033[1;36m╭─[ %s ]──────────────────────────────────────────────────\033[0m\n", filename);
    
    Vulnerability *curr = head;
    while (curr) {
        char *severity_color = "\033[1;33m"; 
        char *icon = "WARNING";
        
        if (strcmp(curr->function_name, "system") == 0 || 
            strcmp(curr->function_name, "popen") == 0 ||
            strstr(curr->issue_type, "Format String")) {
            severity_color = "\033[1;31m"; 
            icon = "CRITICAL";
        }
        
        printf(" \033[1;36m│\033[0m\n");
        printf(" \033[1;36m│\033[0m  \033[1;30m[Line %3d]\033[0m %s%s\033[0m: \033[1m%s\033[0m (%s)\n", 
               curr->line, severity_color, icon, curr->issue_type, curr->function_name);
               
        if (verbose > 0) {
            const char *reason, *suggestion, *example;
            get_recommendation(curr->function_name, curr->issue_type, &reason, &suggestion, &example);
            
            // Wrap reason text only if verbose == 1 (Detailed Recommendation Mode)
            if (verbose == 1) {
                char prefix_buf[64];
                sprintf(prefix_buf, " \033[1;36m│\033[0m    \033[90m");
                print_wrapped(reason, 60, prefix_buf);
                printf("\033[0m\n");
            }
            
            if (example && strlen(example) > 0) {
                 printf(" \033[1;36m│\033[0m    \033[1;32mCode Suggestion:\033[0m\n");
                 
                 // Process example string to indent it
                 char *ex_dup = strdup(example);
                 char *line = strtok(ex_dup, "\n");
                 while(line) {
                     printf(" \033[1;36m│\033[0m    \033[90m│\033[0m %s\n", line);
                     line = strtok(NULL, "\n");
                 }
                 free(ex_dup);
            }
        }
        curr = curr->next;
    }
    // Count issues
    int count = 0;
    Vulnerability *temp = head;
    while (temp) {
        count++;
        temp = temp->next;
    }
    printf("\n     \033[1;30mTOTAL ISSUES FOUND:\033[0m %d\n\n", count);
}

void print_recommendation_report(const char *filename, Vulnerability *head) {
    if (!head) return;
    // Redirect to scan report with verbose=1 for -r (recommendation mode)
    // The previous architecture separated them, but now we can unify the look.
    // However, keeping the function signature.
    print_scan_report(filename, head, 1);
}
