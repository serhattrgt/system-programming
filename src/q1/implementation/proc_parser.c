#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proc_parser.h"

void print_memory_maps() {
    printf("1.1 Memory Segment Analysis\n");
    printf("1.2 List All Memory Segments\n");
    
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { perror("fopen maps"); return; }

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
        strcpy(pathname, ""); // Reset
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
    
    printf("1. Data segment : start = 0x%lx, size = %lu Bytes\n", data_start, data_size);
    printf("2. BSS segment  : start = 0x%lx, size = %lu Bytes\n", bss_start, bss_size);
    printf("3. Heap segment : start = 0x%lx, size = %lu Bytes\n", heap_start, heap_size);
    printf("4. Stack segment: start = 0x%lx, size = %lu Bytes\n", stack_start, stack_size);
    printf("5. Text segment : start = 0x%lx, size = %lu Bytes\n", text_start, text_size);
    
    rewind(f);
    printf("6. Shared Libraries:\n");
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
                 
                 printf("%d. %-14s : 0x%lx-0x%lx (%lu KB) %s\n", 
                        i + 7, name, start, end, size_kb, perms);
                 i++;
            }
        }
    }
    
    rewind(f);
    printf("Shared Libraries Section continued (VDSO):\n"); 

    while (fgets(line, sizeof(line), f)) {
        strcpy(pathname, "");
        sscanf(line, "%lx-%lx %4s %s %s %d %s", 
               &start, &end, perms, offset, dev, &inode, pathname);
        
        if (strcmp(pathname, "[vdso]") == 0) {
             unsigned long size_bytes = end - start;
             unsigned long size_kb = size_bytes / 1024;
             printf("   [vdso]        : 0x%lx-0x%lx (%lu KB) %s\n", 
                    start, end, size_kb, perms);
        }
    }

    fclose(f);
}

void print_memory_status() {
    printf("1.3 Virtual vs Physical Memory Analysis\n");
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) { perror("fopen status"); return; }
    
    char line[256];
    long vm_size = 0, vm_rss = 0, vm_data = 0, vm_stk = 0, vm_exe = 0;
    
    printf("1. Virtual Memory:\n");
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line, "VmSize: %ld", &vm_size);
            printf("2.   VmSize : %ld KB  (Total virtual memory)\n", vm_size);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld", &vm_rss);
            printf("3.   VmRSS  : %ld KB  (Resident in physical memory)\n", vm_rss);
        } else if (strncmp(line, "VmData:", 7) == 0) {
            sscanf(line, "VmData: %ld", &vm_data);
            printf("4.   VmData : %ld KB  (Data segment)\n", vm_data);
        } else if (strncmp(line, "VmStk:", 6) == 0) {
            sscanf(line, "VmStk: %ld", &vm_stk);
            printf("5.   VmStk  : %ld KB  (Stack)\n", vm_stk);
        } else if (strncmp(line, "VmExe:", 6) == 0) {
            sscanf(line, "VmExe: %ld", &vm_exe);
            printf("6.   VmExe  : %ld KB  (Text/Code)\n", vm_exe);
        }
    }
    fclose(f);
    
    if (vm_size > 0) {
        double efficiency = ((double)vm_rss / vm_size) * 100.0;
        printf("8. Memory Efficiency: %.1f%% (Physical/Virtual)\n", efficiency);
    }
}
