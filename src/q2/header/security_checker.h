#ifndef SECURITY_CHECKER_H
#define SECURITY_CHECKER_H

/**
 * Structure representing a single vulnerability found in the code.
 */
typedef struct Vulnerability {
    int line;
    char *function_name; // Function or pattern causing the issue
    char *issue_type;    // Type/Category of the vulnerability
    char *snippet;       // Code snippet containing the issue
    struct Vulnerability *next;
} Vulnerability;

/**
 * Scans a file for known security vulnerabilities.
 * @param filename: Path to the file to scan
 * @param extended_mode: If 1, performs deep checks (format strings, overflow); if 0, basic checks
 * @return Head of the linked list of found vulnerabilities
 */
Vulnerability* scan_file(const char *filename, int extended_mode);

/**
 * Frees the memory allocated for the vulnerability list.
 * @param head: Head of the list
 */
void free_vulnerabilities(Vulnerability *head);

#endif
