#ifndef PROC_PARSER_H
#define PROC_PARSER_H

/**
 * Reads /proc/self/maps to display memory segments and shared libraries.
 */
void print_memory_maps();

/**
 * Reads /proc/self/status to display virtual and resident memory usage.
 */
void print_memory_status();

#endif
