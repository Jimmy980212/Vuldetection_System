#include <stdlib.h>
#include <string.h>

void phase2_buffer_overflow(char *input) {
    char dst[8];
    strcpy(dst, input);
}

void phase2_out_of_bounds(int idx) {
    int values[4] = {0};
    values[idx] = 42;
}

void phase2_use_after_free(void) {
    char *buf = (char *)malloc(16);
    free(buf);
    buf[0] = 'A';
}

void phase2_double_free(void) {
    char *buf = (char *)malloc(16);
    free(buf);
    free(buf);
}

void phase2_null_deref(void) {
    int *ptr = NULL;
    *ptr = 7;
}
