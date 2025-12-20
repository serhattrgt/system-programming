#ifndef CODE_PARSER_H
#define CODE_PARSER_H

#include <stdio.h>

/**
 * Checks if a line contains a specific token key.
 * @param line: The code line to search
 * @param token: The token to search for
 * @return 1 if found, 0 otherwise
 */
int contains_token(const char *line, const char *token);

/**
 * Validates if a print function call is safe against format string attacks.
 * @param line: The code line containing print function
 * @param func: The name of the function (printf, fprintf)
 * @return 1 if potentially vulnerable, 0 if safe
 */
int check_format_string(const char *line, const char *func);

/**
 * Checks for potential integer overflow in malloc calls (e.g. malloc(a * b)).
 * @param line: The code line containing malloc
 * @param prev_line: The previous line of code for context
 * @return 1 if vulnerable pattern found, 0 otherwise
 */
int check_malloc_overflow(const char *line, const char *prev_line);

#endif
