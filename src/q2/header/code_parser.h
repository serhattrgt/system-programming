#ifndef CODE_PARSER_H
#define CODE_PARSER_H

#include <stdio.h>

int contains_token(const char *line, const char *token);
int check_format_string(const char *line, const char *func);
int check_malloc_overflow(const char *line);

#endif
