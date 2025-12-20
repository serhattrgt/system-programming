#ifndef RECOMMENDER_H
#define RECOMMENDER_H

#include "security_checker.h"

/**
 * Prints a basic report of found vulnerabilities.
 * @param filename: The name of the file scanned
 * @param head: Linked list of vulnerabilities
 */
void print_scan_report(const char *filename, Vulnerability *head, int verbose);

/**
 * Prints a detailed report with recommendations and fixes.
 * @param filename: The name of the file scanned
 * @param head: Linked list of vulnerabilities
 */
void print_recommendation_report(const char *filename, Vulnerability *head);

// Print the report for -x mode
void print_extended_report(const char *filename, Vulnerability *head);

#endif
