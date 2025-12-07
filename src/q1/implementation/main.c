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
            printf("\033[H\033[J");
            // Direct call to proc_parser functions or via analyzer?
            // analyzer has printf \n which might be messy or ok.
            run_memory_analysis();
            sleep(monitor_interval);
        }
        return 0;
    }

    // Default
    run_memory_analysis();

    return 0;
}
