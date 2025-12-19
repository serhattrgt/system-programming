#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proc_parser.h"

void print_memory_maps() {
    printf("\n\033[1;36m┌──────────────────────────────────────────────────────────────┐\033[0m\n");
    printf("\033[1;36m│                 MEMORY SEGMENT ANALYSIS                      │\033[0m\n");
    printf("\033[1;36m│                                                              │\033[0m\n");
    printf("\033[1;36m│          \033[1;37mB221202056 - Serhat Turgut                          \033[1;36m│\033[0m\n");
    printf("\033[1;36m│          \033[1;37mB221202045 - Yusuf Okur                             \033[1;36m│\033[0m\n");
    printf("\033[1;36m└──────────────────────────────────────────────────────────────┘\033[0m\n");
    
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("\033[1;31mError opening maps\033[0m"); return; }

    char line[1024];
    unsigned long start, end;
    char perms[5];
    char offset[20];
    char dev[10];
    int inode;
    char pathname[256];

    unsigned long text_start = 0, text_size = 0;
    unsigned long data_start = 0, data_size = 0;
    unsigned long bss_start = 0, bss_size = 0;
    unsigned long heap_start = 0, heap_size = 0;
    unsigned long stack_start = 0, stack_size = 0;


    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len != -1) {
        exe_path[len] = '\0';
    } else {
        strcpy(exe_path, "");
    }
    
    while (fgets(line, sizeof(line), f)) {
        strcpy(pathname, ""); 
        sscanf(line, "%lx-%lx %4s %s %s %d %s", 
                           &start, &end, perms, offset, dev, &inode, pathname);
        
        unsigned long size = end - start;

        if (strstr(pathname, "[heap]")) {
            heap_start = start;
            heap_size = size;
        } else if (strstr(pathname, "[stack]")) {
            stack_start = start;
            stack_size = size;
        } else if (strlen(exe_path) > 0 && strcmp(pathname, exe_path) == 0) {
            if (perms[0] == 'r' && perms[2] == 'x') {
                if (text_start == 0) {
                    text_start = start;
                    text_size = size;
                } else {
                    text_size += size;
                }
            } else if (perms[0] == 'r' && perms[1] == 'w') {
                if (data_start == 0) {
                    data_start = start;
                    data_size = size;
                } else {
                    data_size += size;
                }
            }
        } else if (strcmp(pathname, "") == 0 && data_start != 0 && start == data_start + data_size) {
             if (perms[0] == 'r' && perms[1] == 'w') {
                 bss_start = start;
                 bss_size = size;
             }
        }
    }
    
    printf("\033[1m%-15s │ %-18s │ %-15s\033[0m\n", "SEGMENT", "START ADDRESS", "SIZE (Bytes)");
    printf("\033[1;30m────────────────┼────────────────────┼────────────────\033[0m\n");
    printf("\033[1;32m%-15s\033[0m │ 0x%-16lx │ \033[1;33m%lu\033[0m\n", "Data", data_start, data_size);
    printf("\033[1;32m%-15s\033[0m │ 0x%-16lx │ \033[1;33m%lu\033[0m\n", "BSS", bss_start, bss_size);
    printf("\033[1;34m%-15s\033[0m │ 0x%-16lx │ \033[1;33m%lu\033[0m\n", "Heap", heap_start, heap_size);
    printf("\033[1;35m%-15s\033[0m │ 0x%-16lx │ \033[1;33m%lu\033[0m\n", "Stack", stack_start, stack_size);
    printf("\033[1;36m%-15s\033[0m │ 0x%-16lx │ \033[1;33m%lu\033[0m\n", "Text", text_start, text_size);
    printf("\033[1;30m────────────────┴────────────────────┴────────────────\033[0m\n");
    
    rewind(f);
    printf("\n\033[1;36m┌──────────────────────────────────────────────────────────────┐\033[0m\n");
    printf("\033[1;36m│                   SHARED LIBRARIES                           │\033[0m\n");
    printf("\033[1;36m└──────────────────────────────────────────────────────────────┘\033[0m\n");
    
    int i = 0;
    while (fgets(line, sizeof(line), f)) {
        strcpy(pathname, "");
        sscanf(line, "%lx-%lx %4s %s %s %d %s", 
               &start, &end, perms, offset, dev, &inode, pathname);
        
        if (strstr(pathname, ".so")) {
            unsigned long size_bytes = end - start;
            unsigned long size_kb = size_bytes / 1024;
            if (perms[2] == 'x') {
                 char *name = strrchr(pathname, '/');
                 if (name) name++; else name = pathname;
                 
                 printf(" \033[1;34m%2d.\033[0m \033[1m%-25s\033[0m : \033[37m0x%lx-0x%lx\033[0m (\033[1;33m%lu KB\033[0m) \033[32m%s\033[0m\n", 
                        i + 1, name, start, end, size_kb, perms);
                 i++;
            }
        }
    }
    
    rewind(f);
    
    while (fgets(line, sizeof(line), f)) {
        strcpy(pathname, "");
        sscanf(line, "%lx-%lx %4s %s %s %d %s", 
               &start, &end, perms, offset, dev, &inode, pathname);
        
        if (strcmp(pathname, "[vdso]") == 0) {
             unsigned long size_bytes = end - start;
             unsigned long size_kb = size_bytes / 1024;
             printf(" \033[1;35m[vdso]\033[0m                      : \033[37m0x%lx-0x%lx\033[0m (\033[1;33m%lu KB\033[0m) \033[32m%s\033[0m\n", 
                    start, end, size_kb, perms);
        }
    }

    fclose(f);
}

void print_memory_status() {
    printf("\n\033[1;36m┌──────────────────────────────────────────────────────────────┐\033[0m\n");
    printf("\033[1;36m│             VIRTUAL VS PHYSICAL MEMORY ANALYSIS              │\033[0m\n");
    printf("\033[1;36m└──────────────────────────────────────────────────────────────┘\033[0m\n");

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) { perror("\033[1;31mfopen status\033[0m"); return; }
    
    char line[256];
    long vm_size = 0, vm_rss = 0, vm_data = 0, vm_stk = 0, vm_exe = 0;
    
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line, "VmSize: %ld", &vm_size);
            printf(" \033[1;34m▶\033[0m \033[1mVmSize : \033[1;33m%8ld KB\033[0m  \033[90m(Total virtual memory)\033[0m\n", vm_size);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld", &vm_rss);
            printf(" \033[1;34m▶\033[0m \033[1mVmRSS  : \033[1;33m%8ld KB\033[0m  \033[90m(Resident in physical memory)\033[0m\n", vm_rss);
        } else if (strncmp(line, "VmData:", 7) == 0) {
            sscanf(line, "VmData: %ld", &vm_data);
            printf(" \033[1;34m▶\033[0m \033[1mVmData : \033[1;33m%8ld KB\033[0m  \033[90m(Data segment)\033[0m\n", vm_data);
        } else if (strncmp(line, "VmStk:", 6) == 0) {
            sscanf(line, "VmStk: %ld", &vm_stk);
            printf(" \033[1;34m▶\033[0m \033[1mVmStk  : \033[1;33m%8ld KB\033[0m  \033[90m(Stack)\033[0m\n", vm_stk);
        } else if (strncmp(line, "VmExe:", 6) == 0) {
            sscanf(line, "VmExe: %ld", &vm_exe);
            printf(" \033[1;34m▶\033[0m \033[1mVmExe  : \033[1;33m%8ld KB\033[0m  \033[90m(Text/Code)\033[0m\n", vm_exe);
        }
    }
    fclose(f);
    
    if (vm_size > 0) {
        double efficiency = ((double)vm_rss / vm_size) * 100.0;
        printf("\n \033[1;32m✔ Memory Efficiency\033[0m: \033[1;37m%.1f%%\033[0m \033[90m(Physical/Virtual)\033[0m\n", efficiency);
    }
}
