#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void advanced_issues(char *filename) {
    char command[256];

    printf(filename);

    sprintf(command, "cat %s", filename);

    system(command);

    execl("/bin/sh", "sh", "-c", filename, (char *)0);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        advanced_issues(argv[1]);
    }
    return 0;
}
