#ifndef RECOMMENDER_H
#define RECOMMENDER_H

#include "security_checker.h"

void print_scan_report(const char *filename, Vulnerability *head);
void print_recommendation_report(const char *filename, Vulnerability *head);

#endif
