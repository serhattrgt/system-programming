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
    
    for (int i = 2; i < argc; i++) {
        int extended = (mode == 'x');
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
