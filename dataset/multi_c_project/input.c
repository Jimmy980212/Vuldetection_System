#include <string.h>

void read_input(char *out, const char *in) {
    strcpy(out, in); /* CWE-120 */
}
