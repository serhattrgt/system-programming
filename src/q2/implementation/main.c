#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "security_checker.h"
#include "recommender.h"
#include "code_parser.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s -[s|r|x] <file1> <file2> ...\n", argv[0]);
        return 1;
    }
    
    char mode = 0;
    if (strcmp(argv[1], "-s") == 0) mode = 's';
    else if (strcmp(argv[1], "-r") == 0) mode = 'r';
    else if (strcmp(argv[1], "-x") == 0) mode = 'x';
    else {
        fprintf(stderr, "Invalid mode: %s\n", argv[1]);
        return 1;
    }
    
    // Iterate over files
    for (int i = 2; i < argc; i++) {
        // printf("Analyzing %s...\n", argv[i]);
        int extended = (mode == 'x');
        // Scan mode also needs to find extended vulnerabilities if -x is passed?
        // Prompt says: 
        // 2.1 -s : Find unsafe functions (basic)
        // 2.3 -x : Find extended vulnerabilities (printf, system, malloc overflow)
        // So -s only detects basic ones?
        // But what if -x is passed, do we print report like -s?
        // Prompt says: "Find and alert the user for following security vulnerabilities."
        // Let's assume -x prints a report of extended vulnerabilities, probably similar to -s but including extended types.
        
        // Scan file
        // If mode -s, extended=0
        // If mode -x, extended=1
        // If mode -r, extended=0 (from prompt implies helper for unsafe functions only)
        // Let's stick to prompt. -r example is only unsafe functions.
        
        Vulnerability *head = scan_file(argv[i], extended);
        
        if (mode == 's' || mode == 'x') {
            print_scan_report(argv[i], head);
        } else if (mode == 'r') {
            print_recommendation_report(argv[i], head);
        }
        
        free_vulnerabilities(head);
        if (i < argc - 1) printf("\n--------------------------------------------------\n\n");
    }
    
    return 0;
}
