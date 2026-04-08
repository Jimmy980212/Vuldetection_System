#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_buffer_overflow() {
    char buf[10];
    strcpy(buf, "This string is way too long for the buffer");
    printf("%s\n", buf);
}

void vulnerable_command_injection() {
    char cmd[100];
    char user_input[50];
    fgets(user_input, sizeof(user_input), stdin);
    sprintf(cmd, "echo %s", user_input);
    system(cmd);
}

void vulnerable_unsafe_functions() {
    char buf[100];
    gets(buf);
    sprintf(buf, "Format: %s");
}

int main() {
    vulnerable_buffer_overflow();
    vulnerable_command_injection();
    vulnerable_unsafe_functions();
    return 0;
}