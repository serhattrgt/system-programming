#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "security_checker.h"
#include "recommender.h"
#include "code_parser.h"

int main(int argc, char *argv[]) {
    int show_banner = 1;

    if (argc >= 2 && strcmp(argv[1], "--help") == 0) {
        printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
        printf("\033[1;35m║             CODE SECURITY SCANNER HELP MENU                  ║\033[0m\n");
        printf("\033[1;35m║                                                              ║\033[0m\n");
        printf("\033[1;35m║          \033[1;37mB221202056 - Serhat Turgut                          \033[1;35m║\033[0m\n");
        printf("\033[1;35m║          \033[1;37mB221202045 - Yusuf Okur                             \033[1;35m║\033[0m\n");
        printf("\033[1;35m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n");
        printf(" \033[1;36mUsage:\033[0m ./q2 \033[1m-[s|r|x]\033[0m \033[36m<file1> <file2> ...\033[0m\n\n");
        printf(" \033[1;33mModes:\033[0m\n");
        printf("   \033[1;32m-s\033[0m    Scan for basic vulnerabilities (standard mode).\n");
        printf("   \033[1;32m-r\033[0m    Scan and provide detailed recommendations.\n");
        printf("   \033[1;32m-x\033[0m    Extended scan (includes format string & integer overflow checks).\n\n");
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "\033[1;33mUsage:\033[0m %s \033[1m-[s|r|x]\033[0m \033[36m<file1> <file2> ...\033[0m\n", argv[0]);
        return 1;
    }
    
    char mode = 0;
    if (strcmp(argv[1], "-s") == 0) mode = 's';
    else if (strcmp(argv[1], "-r") == 0) mode = 'r';
    else if (strcmp(argv[1], "-x") == 0) mode = 'x';
    else {
        fprintf(stderr, "\033[1;31mInvalid mode:\033[0m %s\n", argv[1]);
        return 1;
    }
    
    if (show_banner) {
        printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
        printf("\033[1;35m║               CODE SECURITY SCANNER v1.0                     ║\033[0m\n");
        printf("\033[1;35m║                                                              ║\033[0m\n");
        printf("\033[1;35m║          \033[1;37mB221202056 - Serhat Turgut                          \033[1;35m║\033[0m\n");
        printf("\033[1;35m║          \033[1;37mB221202045 - Yusuf Okur                             \033[1;35m║\033[0m\n");
        printf("\033[1;35m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n");
    }

    for (int i = 2; i < argc; i++) {
        int extended = (mode == 'x');
        Vulnerability *head = scan_file(argv[i], extended);
        
        if (mode == 's' || mode == 'x') {
            print_scan_report(argv[i], head, (mode == 'x'));
        } else if (mode == 'r') {
            print_recommendation_report(argv[i], head);
        }
        
        free_vulnerabilities(head);
        if (i < argc - 1) printf("\n\033[1;30m══════════════════════════════════════════════════════════════\033[0m\n\n");
    }
    
    return 0;
}
