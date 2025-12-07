#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "code_parser.h"

// Helper to check token existence
int contains_token(const char *line, const char *token) {
    const char *p = strstr(line, token);
    while (p) {
        // Check boundaries: matched if token is found followed by optional space then '('
        char prev = (p == line) ? ' ' : *(p-1);
        const char *after = p + strlen(token);
        while (isspace(*after)) after++;
        
        if (!isalnum(prev) && prev != '_' && *after == '(') {
            return 1;
        }
        p = strstr(p + 1, token);
    }
    return 0;
}

// Helper to check for format string vulnerability: printf(buf)
int check_format_string(const char *line, const char *func) {
    const char *p = strstr(line, func);
    if (!p) return 0;
    
    // Find opening paren
    const char *paren = strchr(p, '(');
    if (!paren) return 0;
    
    const char *arg = paren + 1;
    while (isspace(*arg)) arg++;
    
    // If fprintf, skip first arg (FILE *fp)
    if (strcmp(func, "fprintf") == 0) {
        const char *comma = strchr(arg, ',');
        if (!comma) return 0;
        arg = comma + 1;
        while (isspace(*arg)) arg++;
    }
    
    if (*arg != '"') {
        return 1; // Suspicious: Argument is not a string literal
    }
    return 0;
}

// Helper for malloc overflow: malloc(a * b)
int check_malloc_overflow(const char *line) {
    const char *p = strstr(line, "malloc");
    if (!p) return 0;
    
    const char *paren = strchr(p, '(');
    if (!paren) return 0;
    
    const char *close_paren = strchr(paren, ')');
    if (!close_paren) return 0;
    
    // Scan between paren and close_paren for '*'
    for (const char *c = paren + 1; c < close_paren; c++) {
        if (*c == '*') return 1;
    }
    return 0;
}
