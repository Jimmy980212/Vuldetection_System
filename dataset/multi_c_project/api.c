#include <stdlib.h>
#include <stdio.h>

void handle_request(const char *name) {
    char cmd[256];
    sprintf(cmd, "echo hello %s", name); /* CWE-78 */
    system(cmd);
}
