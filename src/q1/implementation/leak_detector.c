#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "leak_detector.h"

typedef struct AllocationInfo {
    void *ptr;
    size_t size;
    const char *file;
    int line;
    struct AllocationInfo *next;
} AllocationInfo;

static AllocationInfo *head = NULL;
static size_t total_allocations = 0;
static size_t total_freed = 0;

void* tracked_malloc(size_t size, const char *file, int line) {
    void *ptr = malloc(size);
    if (!ptr) return NULL;

    AllocationInfo *node = (AllocationInfo*)malloc(sizeof(AllocationInfo));
    node->ptr = ptr;
    node->size = size;
    node->file = file;
    node->line = line;
    node->next = head;
    head = node;

    total_allocations++;
    return ptr;
}

void tracked_free(void *ptr, const char *file, int line) {
    AllocationInfo **curr = &head;
    while (*curr) {
        if ((*curr)->ptr == ptr) {
            AllocationInfo *temp = *curr;
            *curr = (*curr)->next;
            free(temp);
            free(ptr);
            total_freed++;
            return;
        }
        curr = &((*curr)->next);
    }
}

void print_leak_report() {
    printf("\n");
    if (total_allocations - total_freed == 0 && !head) {
        printf("\033[1;32m┌──────────────────────────────────────────────────────────────┐\033[0m\n");
        printf("\033[1;32m│                   NO MEMORY LEAKS DETECTED                   │\033[0m\n");
        printf("\033[1;32m│                                                              │\033[0m\n");
        printf("\033[1;32m│          \033[1;37mB221202056 - Serhat Turgut                          \033[1;32m│\033[0m\n");
        printf("\033[1;32m│          \033[1;37mB221202045 - Yusuf Okur                             \033[1;32m│\033[0m\n");
        printf("\033[1;32m└──────────────────────────────────────────────────────────────┘\033[0m\n");
    } else {
        printf("\033[1;31m┌──────────────────────────────────────────────────────────────┐\033[0m\n");
        printf("\033[1;31m│                    MEMORY LEAK REPORT                        │\033[0m\n");
        printf("\033[1;31m│                                                              │\033[0m\n");
        printf("\033[1;31m│          \033[1;37mB221202056 - Serhat Turgut                          \033[1;31m│\033[0m\n");
        printf("\033[1;31m│          \033[1;37mB221202045 - Yusuf Okur                             \033[1;31m│\033[0m\n");
        printf("\033[1;31m└──────────────────────────────────────────────────────────────┘\033[0m\n");
    }
    
    printf("\n \033[1;34m▶\033[0m Total allocations : \033[1m%lu\033[0m\n", total_allocations);
    printf(" \033[1;34m▶\033[0m Total freed       : \033[1m%lu\033[0m\n", total_freed);
    
    size_t leaked_count = 0;
    AllocationInfo *curr = head;
    while (curr) {
        leaked_count++;
        curr = curr->next;
    }
    
    if (leaked_count > 0) {
        printf(" \033[1;31m▶\033[0m Leaked blocks     : \033[1;31m%lu\033[0m\n", leaked_count);
        printf("\n\033[1;31m  LEAK DETAILS:\033[0m\n");
        printf("\033[1;30m  ────────────────────────────────────────────────────────────\033[0m\n");
    
        curr = head;
        int block_num = 1;
        while (curr) {
            printf("  \033[1;31m[%d]\033[0m \033[1;33m%lu bytes\033[0m at \033[37m%p\033[0m\n", block_num++, curr->size, curr->ptr);
            printf("      \033[90mAllocated at:\033[0m \033[36m%s\033[0m:\033[1;33m%d\033[0m\n", curr->file, curr->line);
            if (curr->next) printf("\n");
            curr = curr->next;
        }
        printf("\033[1;30m  ────────────────────────────────────────────────────────────\033[0m\n");
    } else {
         printf(" \033[1;32m▶\033[0m Leaked blocks     : \033[1;32m0\033[0m\n");
    }
}

void run_leak_check() {
    printf("\033[1;36m┌──────────────────────────────────────────────────────────────┐\033[0m\n");
    printf("\033[1;36m│                  RUNNING LEAK DETECTOR...                    │\033[0m\n");
    printf("\033[1;36m└──────────────────────────────────────────────────────────────┘\033[0m\n");
    char *p1 = MALLOC(100);
    char *p2 = MALLOC(100);
    FREE(p1);

    print_leak_report();
    
    
    FREE(p2); 
}
