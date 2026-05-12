import os
from typing import List


def _block_buffer_overflow(i: int) -> str:
    return f"""
void buffer_overflow_func_{i}(char *input) {{
    char buffer[64];
    strcpy(buffer, input);
    printf("Copied: %s\\n", buffer);
}}

void buffer_overflow_gets_{i}() {{
    char user_input[256];
    printf("Enter input: ");
    gets(user_input);
    buffer_overflow_func_{i}(user_input);
}}
"""


def _block_use_after_free(i: int) -> str:
    return f"""
void use_after_free_func_{i}() {{
    int *ptr = (int*)malloc(sizeof(int) * 10);
    if (!ptr) return;
    *ptr = 42;
    free(ptr);
    *ptr = 100;
    printf("After free: %d\\n", *ptr);
}}
"""


def _block_double_free(i: int) -> str:
    return f"""
void double_free_func_{i}() {{
    int *ptr = (int*)malloc(sizeof(int) * 10);
    if (!ptr) return;
    free(ptr);
    free(ptr);
}}
"""


def _block_null_pointer(i: int) -> str:
    return f"""
void null_pointer_deref_{i}() {{
    int *ptr = NULL;
    *ptr = 42;
}}
"""


def _block_format_string(i: int) -> str:
    # 含有 % 符号，便于你当前的 mock 逻辑触发
    return f"""
void format_string_vuln_{i}() {{
    char user_format[64] = "%x-%x-%x";
    printf(user_format);
}}
"""


def _block_integer_overflow(i: int) -> str:
    return f"""
void integer_overflow_{i}() {{
    int a = INT_MAX;
    int b = a + 1;
    printf("%d + 1 = %d\\n", a, b);
}}
"""


def _block_command_injection(i: int) -> str:
    return f"""
void command_injection_{i}() {{
    char user_input[100];
    char cmd[200];
    printf("Enter filename: ");
    gets(user_input);
    sprintf(cmd, "cat %s", user_input);
    system(cmd);
}}
"""


def _block_path_traversal(i: int) -> str:
    return f"""
void path_traversal_{i}() {{
    char filename[256];
    char path[512] = "/var/www/";
    printf("Enter filename: ");
    gets(filename);
    strcat(path, filename);
    FILE *f = fopen(path, "r");
    if (f) {{
        fclose(f);
    }}
}}
"""


def _block_hardcoded_creds(i: int) -> str:
    return f"""
void hardcoded_cred_check_{i}() {{
    char input[100];
    char *password = "secret123_{i}!";
    printf("Enter password: ");
    gets(input);
    if (strcmp(input, password) == 0) {{
        printf("Access granted\\n");
    }} else {{
        printf("Access denied\\n");
    }}
}}
"""


def _block_race_condition(i: int) -> str:
    # 同时包含：
    # - CWE-362: pthread/mutex 等关键字
    # - CWE-367: access/stat + fopen 的 TOCTOU 形态
    return f"""
pthread_mutex_t mutex_{i} = PTHREAD_MUTEX_INITIALIZER;

void* race_thread_{i}(void* arg) {{
    pthread_mutex_lock(&mutex_{i});
    pthread_mutex_unlock(&mutex_{i});
    return NULL;
}}

void race_condition_{i}() {{
    struct stat st;
    pthread_t t;
    pthread_create(&t, NULL, race_thread_{i}, NULL);
    pthread_join(t, NULL);

    if (access("/tmp/file", F_OK) == 0) {{
        FILE *f = fopen("/tmp/file", "r");
        if (f) fclose(f);
    }}

    if (stat("/tmp/file", &st) == 0) {{
        // 占位
        int x = st.st_size + {i};
        (void)x;
    }}
}}
"""


def generate_big_c_file(output_path: str, blocks: int = 200) -> str:
    """
    生成“大文件”用于压测：通过重复多个漏洞触发片段来形成大规模输入。
    返回实际写入的文件路径。
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    header = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
"""

    body_blocks: List[str] = []
    for i in range(blocks):
        # 每个 block 包含多类漏洞片段（更利于验证 CWE 覆盖与吞吐）
        body_blocks.append(_block_buffer_overflow(i))
        body_blocks.append(_block_use_after_free(i))
        body_blocks.append(_block_double_free(i))
        body_blocks.append(_block_null_pointer(i))
        body_blocks.append(_block_format_string(i))
        body_blocks.append(_block_integer_overflow(i))
        body_blocks.append(_block_command_injection(i))
        body_blocks.append(_block_path_traversal(i))
        body_blocks.append(_block_hardcoded_creds(i))
        body_blocks.append(_block_race_condition(i))

    main = f"""
int main(void) {{
"""
    # 简单调用，避免部分解析器认为“无实现”
    # （即使不执行，也不会影响你当前基于关键字/Joern 的分析）
    for i in range(blocks):
        main += f"    buffer_overflow_gets_{i}();\n"
        main += f"    use_after_free_func_{i}();\n"
        main += f"    double_free_func_{i}();\n"
        main += f"    null_pointer_deref_{i}();\n"
        main += f"    format_string_vuln_{i}();\n"
        main += f"    integer_overflow_{i}();\n"
        main += f"    command_injection_{i}();\n"
        main += f"    path_traversal_{i}();\n"
        main += f"    hardcoded_cred_check_{i}();\n"
        main += f"    race_condition_{i}();\n"
    main += "    return 0;\n}\n"

    content = header + "\n" + "\n".join(body_blocks) + "\n" + main
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path


def _java_block_sqli(i: int) -> str:
    return f"""
    public void sqli_{i}(java.sql.Connection conn, String userInput) throws Exception {{
        java.sql.Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name='" + userInput + "'";
        stmt.executeQuery(sql);
    }}
"""


def _java_block_exec(i: int) -> str:
    return f"""
    public void cmd_{i}(String command) throws Exception {{
        Runtime.getRuntime().exec(command);
    }}
"""


def _java_block_deser_to_exec(i: int) -> str:
    return f"""
    public void deser_to_exec_{i}() throws Exception {{
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos);
        oos.writeObject("calc");
        oos.flush();
        byte[] data = bos.toByteArray();

        java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(data));
        String cmd = (String) ois.readObject();
        Runtime.getRuntime().exec(cmd);
    }}
"""


def _java_block_hardcoded_cred(i: int) -> str:
    # Keep the "Use of Hard-coded Credentials" phrase for high-signal detection
    return f"""
    public void hardcodedCred_{i}() throws Exception {{
        String url = "jdbc:mysql://localhost:3306/testdb";
        String user = "root";
        String password = "password"; // Use of Hard-coded Credentials
        java.sql.Connection conn = java.sql.DriverManager.getConnection(url, user, password);
        conn.close();
    }}
"""


def _java_block_race(i: int) -> str:
    return f"""
    public void race_{i}() {{
        final Holder h = new Holder();
        new Thread(new Runnable() {{
            @Override public void run() {{
                h.x = 1;
            }}
        }}).start();
        while (h.x == 0) {{
            Thread.yield();
        }}
    }}
"""


def generate_big_java_file(output_path: str, target_lines: int = 10_000) -> str:
    """
    生成“约 10000 行级”的 Java 文件用于压测。
    返回实际写入的文件路径。
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    header = """import java.io.*;
import java.sql.*;

public class BigJavaTest {
    static class Holder { public int x = 0; }

"""

    blocks: List[str] = []
    # Roughly: each i adds ~30-45 lines; start with 250 blocks then pad.
    for i in range(260):
        blocks.append(_java_block_sqli(i))
        blocks.append(_java_block_exec(i))
        if i % 3 == 0:
            blocks.append(_java_block_deser_to_exec(i))
        if i % 5 == 0:
            blocks.append(_java_block_hardcoded_cred(i))
        if i % 4 == 0:
            blocks.append(_java_block_race(i))

    main = """    public static void main(String[] args) throws Exception {
        BigJavaTest t = new BigJavaTest();
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/testdb", "root", "password"); // Use of Hard-coded Credentials
        for (int i = 0; i < 50; i++) {
            t.sqli_0(conn, "u");
            t.cmd_0("id");
            t.race_0();
        }
        conn.close();
    }
}
"""

    content = header + "\n".join(blocks) + "\n" + main
    # Pad to target lines with harmless filler if needed
    lines = content.splitlines()
    if len(lines) < int(target_lines):
        pad_n = int(target_lines) - len(lines)
        lines.extend([f"// filler line {j}" for j in range(pad_n)])
        content = "\n".join(lines) + "\n"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path

