#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// 1. 缓冲区溢出漏洞
void buffer_overflow(char *input) {
    char buffer[10];
    // 明显的缓冲区溢出
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

// 2. 使用后释放漏洞
void use_after_free() {
    char *ptr = (char *)malloc(100);
    if (ptr) {
        free(ptr);
        // 使用已释放的内存
        strcpy(ptr, "Hello");
        printf("%s\n", ptr);
    }
}

// 3. 空指针解引用漏洞
void null_pointer_dereference() {
    char *ptr = NULL;
    // 解引用空指针
    *ptr = 'a';
}

// 4. 整数溢出漏洞
void integer_overflow() {
    uint32_t a = 0xFFFFFFFF;
    uint32_t b = 1;
    // 整数溢出
    uint32_t c = a + b;
    printf("a + b = %u\n", c);
}

// 5. 格式化字符串漏洞
void format_string_vulnerability(char *input) {
    // 直接使用用户输入作为格式化字符串
    printf(input);
}

// 6. 栈溢出漏洞
void stack_overflow(int depth) {
    char buffer[100];
    if (depth > 0) {
        // 递归调用导致栈溢出
        stack_overflow(depth - 1);
    }
}

// 7. 堆溢出漏洞
void heap_overflow() {
    char *ptr = (char *)malloc(10);
    if (ptr) {
        // 写入超过分配大小的数据
        strcpy(ptr, "This string is way too long for the allocated buffer");
        printf("%s\n", ptr);
        free(ptr);
    }
}

// 8. 命令注入漏洞
void command_injection(char *input) {
    char command[100];
    // 直接将用户输入拼接到命令中
    sprintf(command, "echo %s", input);
    system(command);
}

// 9. 硬编码密码
void hardcoded_password() {
    // 硬编码的密码
    char password[] = "secret123";
    printf("Password: %s\n", password);
}

// 10. 不安全的内存管理
void unsafe_memory_management() {
    char *ptr = (char *)malloc(100);
    // 没有检查分配是否成功
    strcpy(ptr, "Hello");
    // 没有释放内存，导致内存泄漏
}

int main() {
    // 测试缓冲区溢出
    char *long_input = "this is a very long input that will definitely overflow the buffer";
    buffer_overflow(long_input);
    
    // 测试使用后释放
    use_after_free();
    
    // 测试空指针解引用
    // null_pointer_dereference(); // 取消注释会导致程序崩溃
    
    // 测试整数溢出
    integer_overflow();
    
    // 测试格式化字符串漏洞
    format_string_vulnerability("Hello %s\n");
    
    // 测试栈溢出
    // stack_overflow(100000); // 取消注释会导致栈溢出
    
    // 测试堆溢出
    heap_overflow();
    
    // 测试命令注入
    command_injection("test");
    
    // 测试硬编码密码
    hardcoded_password();
    
    // 测试不安全的内存管理
    unsafe_memory_management();
    
    return 0;
}