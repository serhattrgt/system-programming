#ifndef LEAK_DETECTOR_H
#define LEAK_DETECTOR_H

#include <stdlib.h>

/**
 * Allocates memory and tracks it for leak detection.
 * @param size: Size in bytes
 * @param file: Source file name
 * @param line: Line number of allocation
 */
void* tracked_malloc(size_t size, const char *file, int line);

/**
 * Frees memory and removes it from the tracking list.
 * @param ptr: Pointer to memory to free
 * @param file: Source file name calling free (unused in logic but useful for logging)
 * @param line: Line number calling free
 */
void tracked_free(void *ptr, const char *file, int line);

/**
 * Prints a report of any detected memory leaks.
 */
void print_leak_report();

/**
 * Runs a demonstration of memory leak detection.
 */
void run_leak_check();

#define MALLOC(size) tracked_malloc(size, __FILE__, __LINE__)
#define FREE(ptr) tracked_free(ptr, __FILE__, __LINE__)

#endif
