#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "security_checker.h"
#include "code_parser.h"

Vulnerability* add_vuln(Vulnerability *head, int line, const char *func, const char *type, const char *snippet) {
    Vulnerability *node = (Vulnerability*)malloc(sizeof(Vulnerability));
    node->line = line;
    node->function_name = strdup(func);
    node->issue_type = strdup(type);
    
    // Trim newline from snippet
    node->snippet = strdup(snippet);
    char *n = strrchr(node->snippet, '\n');
    if (n) *n = '\0';
    
    node->next = head;
    return node;
}

Vulnerability* scan_file(const char *filename, int extended_mode) {
    FILE *f = fopen(filename, "r");
    if (!f) { perror("fopen"); return NULL; }
    
    Vulnerability *head = NULL;
    char line[1024];
    int line_num = 0;
    
    const char *unsafe_funcs[] = {"strcpy", "strcat", "sprintf", "gets", "scanf", NULL};
    const char *time_funcs[] = {"gmtime", "localtime", "ctime", "asctime", NULL};
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        for (int i = 0; unsafe_funcs[i]; i++) {
            if (contains_token(line, unsafe_funcs[i])) {
                head = add_vuln(head, line_num, unsafe_funcs[i], "Unsafe Function", line);
            }
        }
        
        for (int i = 0; time_funcs[i]; i++) {
            if (contains_token(line, time_funcs[i])) {
                head = add_vuln(head, line_num, time_funcs[i], "Thread-Unsafe Time Function", line);
            }
        }
        
        if (extended_mode) {
            if (contains_token(line, "printf")) {
                if (check_format_string(line, "printf")) {
                    head = add_vuln(head, line_num, "printf", "Format String Vulnerability", line);
                }
            }
            if (contains_token(line, "fprintf")) {
                if (check_format_string(line, "fprintf")) {
                    head = add_vuln(head, line_num, "fprintf", "Format String Vulnerability", line);
                }
            }
            
            if (contains_token(line, "system")) {
                 head = add_vuln(head, line_num, "system", "Command Injection", line);
            }
            if (contains_token(line, "popen")) {
                 head = add_vuln(head, line_num, "popen", "Command Injection", line);
            }
            
            if (contains_token(line, "malloc")) {
                if (check_malloc_overflow(line)) {
                     head = add_vuln(head, line_num, "malloc", "Integer Overflow Risk", line);
                }
            }
        }
    }
    
    fclose(f);
    
    Vulnerability *prev = NULL, *curr = head, *next;
    while (curr) {
        next = curr->next;
        curr->next = prev;
        prev = curr;
        curr = next;
    }
    return prev;
}

void free_vulnerabilities(Vulnerability *head) {
    while (head) {
        Vulnerability *temp = head;
        head = head->next;
        free(temp->function_name);
        free(temp->issue_type);
        free(temp->snippet);
        free(temp);
    }
}
