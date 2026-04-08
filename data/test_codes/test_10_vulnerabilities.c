#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. 缓冲区溢出 (Buffer Overflow)
void buffer_overflow() {
    char dest[10];
    char src[100] = "This is a long string that will cause buffer overflow";
    strcpy(dest, src); // 漏洞：strcpy没有边界检查
}

// 2. 使用未初始化变量 (Uninitialized Variable)
int uninitialized_variable() {
    int x; // 未初始化
    return x; // 漏洞：使用未初始化的变量
}

// 3. 空指针解引用 (Null Pointer Dereference)
void null_pointer_dereference() {
    int *ptr = NULL;
    *ptr = 42; // 漏洞：解引用空指针
}

// 4. 内存泄漏 (Memory Leak)
void memory_leak() {
    int *ptr = (int*)malloc(100 * sizeof(int));
    // 漏洞：没有释放内存
    return;
}

// 5. 整数溢出 (Integer Overflow)
void integer_overflow() {
    int a = 2147483647; // int的最大值
    int b = 1;
    int c = a + b; // 漏洞：整数溢出
}

// 6. 格式化字符串漏洞 (Format String Vulnerability)
void format_string_vulnerability(char *user_input) {
    printf(user_input); // 漏洞：直接使用用户输入作为格式字符串
}

// 7. 栈溢出 (Stack Overflow)
void stack_overflow(int depth) {
    char buffer[1024];
    if (depth > 0) {
        stack_overflow(depth - 1); // 漏洞：递归导致栈溢出
    }
}

// 8. 条件竞争 (Race Condition)
int global_counter = 0;
void race_condition() {
    // 漏洞：多线程环境下的条件竞争
    global_counter++;
}

// 9. 不安全的内存分配 (Unsafe Memory Allocation)
void unsafe_memory_allocation() {
    int size;
    printf("Enter size: ");
    scanf("%d", &size);
    char *buffer = (char*)malloc(size); // 漏洞：用户控制的内存分配
    free(buffer);
}

// 10. 命令注入 (Command Injection)
void command_injection(char *user_input) {
    char cmd[256];
    sprintf(cmd, "echo %s", user_input); // 漏洞：用户输入直接拼接到命令中
    system(cmd);
}

int main() {
    char user_input[100];
    
    printf("Testing 10 common vulnerabilities\n");
    
    // 测试缓冲区溢出
    buffer_overflow();
    
    // 测试未初始化变量
    int result = uninitialized_variable();
    printf("Uninitialized variable result: %d\n", result);
    
    // 测试空指针解引用
    // null_pointer_dereference(); // 取消注释会导致程序崩溃
    
    // 测试内存泄漏
    memory_leak();
    
    // 测试整数溢出
    integer_overflow();
    
    // 测试格式化字符串漏洞
    strcpy(user_input, "Hello %s %d");
    format_string_vulnerability(user_input);
    
    // 测试栈溢出
    // stack_overflow(10000); // 取消注释会导致程序崩溃
    
    // 测试条件竞争
    race_condition();
    
    // 测试不安全的内存分配
    unsafe_memory_allocation();
    
    // 测试命令注入
    strcpy(user_input, "test; rm -rf /");
    command_injection(user_input);
    
    printf("Test completed\n");
    return 0;
}