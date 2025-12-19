#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "memory_analyzer.h"
#include "leak_detector.h"
#include "proc_parser.h"

int main(int argc, char *argv[]) {
    int monitor_mode = 0;
    int monitor_interval = 0;
    int leak_check_mode = 0;
    int all_mode = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "--monitor") == 0) {
            monitor_mode = 1;
            if (argc > 2) {
                monitor_interval = atoi(argv[2]);
            } else {
                fprintf(stderr, "Error: --monitor requires an interval.\n");
                return 1;
            }
        } else if (strcmp(argv[1], "--leak-check") == 0) {
            leak_check_mode = 1;
        } else if (strcmp(argv[1], "--all") == 0) {
            all_mode = 1;
        } else if (strcmp(argv[1], "--help") == 0) {
            printf("\n\033[1;35m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
            printf("\033[1;35m║                   MEMORY ANALYZER HELP MENU                  ║\033[0m\n");
            printf("\033[1;35m║                                                              ║\033[0m\n");
            printf("\033[1;35m║          \033[1;37mB221202056 - Serhat Turgut                          \033[1;35m║\033[0m\n");
            printf("\033[1;35m║          \033[1;37mB221202045 - Yusuf Okur                             \033[1;35m║\033[0m\n");
            printf("\033[1;35m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n");
            printf(" \033[1;36mUsage:\033[0m ./q1 [OPTIONS]\n\n");
            printf(" \033[1;33mOptions:\033[0m\n");
            printf("   \033[1;32m--monitor <S>\033[0m    Run in live monitor mode, refreshing every S seconds.\n");
            printf("   \033[1;32m--leak-check\033[0m     Run memory leak detection test.\n");
            printf("   \033[1;32m--all\033[0m            Run both memory analysis and leak check.\n");
            printf("   \033[1;32m<no args>\033[0m        Run single-shot memory analysis.\n\n");
            return 0;
        }
    }

    if (all_mode) {
        run_memory_analysis();
        printf("\n");
        run_leak_check();
        return 0;
    }

    if (leak_check_mode) {
        run_leak_check();
        return 0;
    }

    if (monitor_mode) {
        while (1) {
            system("clear"); 
            printf("\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
            printf("\033[1;36m║               LIVE MEMORY MONITOR DASHBOARD                  ║\033[0m\n");
            printf("\033[1;36m║                                                              ║\033[0m\n");
            printf("\033[1;36m║          \033[1;37mB221202056 - Serhat Turgut                          \033[1;36m║\033[0m\n");
            printf("\033[1;36m║          \033[1;37mB221202045 - Yusuf Okur                             \033[1;36m║\033[0m\n");
            printf("\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n");
            run_memory_analysis();
            printf("\n\033[90m[Ctrl+C to Exit]  Refreshing in %d seconds...\033[0m\n", monitor_interval);
            fflush(stdout); 
            sleep(monitor_interval);
        }
        return 0;
    }

    run_memory_analysis();

    return 0;
}
