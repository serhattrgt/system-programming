#ifndef SECURITY_CHECKER_H
#define SECURITY_CHECKER_H

typedef struct Vulnerability {
    int line;
    char *function_name; // strcpy gibi bir method ismi olcak 
    char *issue_type;    // burası tipi. yani "Unsafe Function" gibi
    char *snippet;
    struct Vulnerability *next;
} Vulnerability;

Vulnerability* scan_file(const char *filename, int extended_mode);
void free_vulnerabilities(Vulnerability *head);

#endif
