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
    printf("1. Memory Leak Report:\n");
    printf("  Total allocations : %lu\n", total_allocations);
    printf("  Total freed       : %lu\n", total_freed);
    
    size_t leaked_count = 0;
    AllocationInfo *curr = head;
    while (curr) {
        leaked_count++;
        curr = curr->next;
    }
    printf("  Leaked blocks     : %lu\n", leaked_count);
    printf("\n");

    curr = head;
    int block_num = 1;
    while (curr) {
        printf("  Block #%d: %lu bytes at %p\n", block_num++, curr->size, curr->ptr);
        printf("    Allocated at: %s:%d\n", curr->file, curr->line);
        curr = curr->next;
    }
}

void run_leak_check() {
    printf("--- Running Leak Check ---\n");
    // Example from prompt
    char *p1 = MALLOC(100);
    char *p2 = MALLOC(200);
    FREE(p1);
    // p2 not freed -> LEAK!
    print_leak_report();
    
    // Cleanup for clean exit if needed
    FREE(p2); 
}
