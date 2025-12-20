#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "code_parser.h"

int contains_token(const char *line, const char *token) {
    const char *p = strstr(line, token);
    while (p) {
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

int check_format_string(const char *line, const char *func) {
    const char *p = strstr(line, func);
    if (!p) return 0;
    
    const char *paren = strchr(p, '(');
    if (!paren) return 0;
    
    const char *arg = paren + 1;
    while (isspace(*arg)) arg++;
    
    if (strcmp(func, "fprintf") == 0) {
        const char *comma = strchr(arg, ',');
        if (!comma) return 0;
        arg = comma + 1;
        while (isspace(*arg)) arg++;
    }
    
    if (*arg != '"') {
        return 1;
    }
    return 0;
}

int check_malloc_overflow(const char *line, const char *prev_line) {
    const char *p = strstr(line, "malloc");
    if (!p) return 0;
    
    // Check previous line for safety check (simple heuristic)
    if (prev_line && strstr(prev_line, "SIZE_MAX") && strstr(prev_line, "/")) {
        return 0;
    }
    
    const char *paren = strchr(p, '(');
    if (!paren) return 0;
    
    const char *close_paren = strchr(paren, ')');
    if (!close_paren) return 0;
    
    for (const char *c = paren + 1; c < close_paren; c++) {
        if (*c == '*') return 1;
    }
    return 0;
}
