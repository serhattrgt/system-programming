#include <stdio.h>
#include "proc_parser.h"
#include "memory_analyzer.h"

void run_memory_analysis() {
    print_memory_maps();
    printf("\n");
    print_memory_status();
}
