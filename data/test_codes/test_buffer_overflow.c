#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    // 明显的缓冲区溢出
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

int main() {
    char *long_input = "this is a very long input that will definitely overflow the buffer";
    vulnerable_function(long_input);
    return 0;
}
