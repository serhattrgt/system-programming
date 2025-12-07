#ifndef SECURITY_CHECKER_H
#define SECURITY_CHECKER_H

typedef struct Vulnerability {
    int line;
    char *function_name; // e.g. "strcpy"
    char *issue_type;    // e.g. "Unsafe Function", "Format String Vulnerability"
    char *snippet;       // Line content
    struct Vulnerability *next;
} Vulnerability;

Vulnerability* scan_file(const char *filename, int extended_mode);
void free_vulnerabilities(Vulnerability *head);

#endif
