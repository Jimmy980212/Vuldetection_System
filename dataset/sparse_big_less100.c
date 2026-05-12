#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void run_cmd(const char *user) {
    char cmd[256];
    sprintf(cmd, "echo %s", user); /* CWE-78 */
    system(cmd);
}

static void unsafe_copy(const char *src) {
    char buf[32];
    strcpy(buf, src); /* CWE-120 */
    printf("%s\n", buf);
}

int main(int argc, char **argv) {
    const char *in = argc > 1 ? argv[1] : "demo";
    run_cmd(in);
    unsafe_copy(in);
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Sparse-big C file generator output.
 * - Many benign lines to simulate huge file
 * - Few vulnerability snippets (<100) scattered across file
 */

static int benign_fn_0(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_1(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_2(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_3(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_4(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_5(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_6(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_7(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_8(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_9(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_10(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_11(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_12(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_13(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_14(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_15(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_16(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_17(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_18(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_19(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_20(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_21(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_22(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_0(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_23(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_24(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_25(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_26(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_27(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_28(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_29(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_30(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_31(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_32(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_33(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_34(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_35(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_36(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_37(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_38(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_39(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_40(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_1(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_41(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_42(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_43(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_44(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_45(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_46(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_47(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-22
static void vuln_path_2(const char *name) {
  char path[256] = "/tmp/";
  strcat(path, name);
  FILE *f = fopen(path, "r");
  if (f) fclose(f);
}

static int benign_fn_48(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_49(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_3(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_50(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_51(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_52(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_4(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_53(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_54(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_55(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_56(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_57(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_58(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_59(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_60(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_61(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_62(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_63(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_5(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_64(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_65(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_66(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_67(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_68(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_69(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_70(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_71(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_72(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_73(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_74(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_75(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_76(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_77(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_78(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_79(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_6(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_80(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_81(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_82(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_83(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_84(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_85(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_86(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_87(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_88(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_89(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_90(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_91(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_92(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_93(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_94(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_95(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_96(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_97(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_98(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_99(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_100(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_101(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_102(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_103(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_104(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_105(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_106(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_107(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_108(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_109(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_110(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_7(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_111(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_112(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_113(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_114(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_115(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_116(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_117(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_118(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_119(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_120(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_121(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_122(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_123(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_124(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_125(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_126(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_127(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_128(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_129(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_130(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_131(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_132(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_133(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_134(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_135(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_8(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_136(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_137(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_138(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_139(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_140(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_141(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_142(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_9(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_143(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_144(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_145(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_146(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_147(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_148(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_149(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_150(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-134
static void vuln_fmt_10(const char *fmt) {
  printf(fmt);
}

static int benign_fn_151(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_152(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_153(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_154(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_155(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_156(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_157(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_158(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_159(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_160(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_161(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_162(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_163(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_164(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_165(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_166(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_167(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_168(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_169(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_170(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_171(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_172(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_11(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_173(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_174(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_12(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_175(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_176(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_13(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_177(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_178(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_179(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_180(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_181(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_182(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_183(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_14(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_184(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_185(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_186(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_187(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_188(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_189(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_190(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_191(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_192(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_193(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_15(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_194(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_16(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_195(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_196(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_197(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_198(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_199(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_200(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_201(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_202(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_203(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_204(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_205(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_206(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_207(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_208(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_209(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_210(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_211(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_212(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_213(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_214(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_215(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_216(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_217(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_218(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_219(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_220(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_221(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_222(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_223(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_224(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_225(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_226(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_227(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_228(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_229(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_230(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_231(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_232(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_233(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_234(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_235(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_17(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_236(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_237(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_238(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_239(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_240(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_241(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_242(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_243(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_244(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_245(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_246(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_247(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_248(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_249(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_250(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_251(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_252(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_253(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_254(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_255(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_256(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_257(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_258(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_259(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_260(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_261(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_262(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_263(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_264(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_265(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_266(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_267(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_268(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_269(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_270(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_271(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_272(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_273(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_274(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-78
static void vuln_cmd_18(const char *arg) {
  char cmd[256];
  sprintf(cmd, "echo %s", arg);
  system(cmd);
}

static int benign_fn_275(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_276(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_277(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_278(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_279(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_280(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_281(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_282(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_19(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_283(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_284(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_285(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_286(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_287(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_288(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_289(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_290(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_291(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_292(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_293(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_294(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_295(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_296(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_297(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_298(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_299(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_300(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_301(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_302(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_303(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_304(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_305(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_306(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_307(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_308(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_309(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_20(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_310(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_311(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_312(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_313(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_314(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_315(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_316(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_317(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_318(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_319(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_320(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_321(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_21(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_322(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_323(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_324(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_325(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_326(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_327(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_328(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_329(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_330(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_331(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_332(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_333(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_334(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_335(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_336(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_337(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_338(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_339(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_340(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_341(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_342(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_343(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_344(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_345(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_346(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_347(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_348(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_349(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_350(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_351(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_352(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_353(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_354(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_355(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_356(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_357(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_358(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_359(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_360(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_361(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_362(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_363(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_364(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_365(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_366(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_367(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_368(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_369(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_370(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_371(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_372(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_373(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-134
static void vuln_fmt_22(const char *fmt) {
  printf(fmt);
}

static int benign_fn_374(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_375(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_376(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_377(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_378(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_379(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_380(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_381(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_382(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_383(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_384(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_385(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_386(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_387(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_388(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_389(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_390(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-119
static void vuln_overflow_23(const char *arg) {
  char buf[64];
  strcpy(buf, arg);
  puts(buf);
}

static int benign_fn_391(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_392(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_393(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_394(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_395(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_396(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_397(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_398(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_399(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_400(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_401(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_402(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_403(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_404(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_405(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_406(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_407(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_408(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_409(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_410(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_411(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_412(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_413(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-134
static void vuln_fmt_24(const char *fmt) {
  printf(fmt);
}

static int benign_fn_414(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_415(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_416(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_417(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_418(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_419(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_420(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_421(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_422(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_423(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_424(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-476
static void vuln_null_25(void) {
  int *p = 0;
  *p = 42;
}

static int benign_fn_425(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_426(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_427(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_428(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_429(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_430(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_431(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_432(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_433(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

// VULNERABILITY CWE-22
static void vuln_path_26(const char *name) {
  char path[256] = "/tmp/";
  strcat(path, name);
  FILE *f = fopen(path, "r");
  if (f) fclose(f);
}

static int benign_fn_434(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_435(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_436(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_437(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_438(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_439(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_440(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_441(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_442(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_443(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_444(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_445(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_446(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_447(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_448(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_449(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_450(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_451(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_452(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_453(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
  acc = (acc * 33 + 5) ^ (acc >> 1);
  acc = (acc * 33 + 6) ^ (acc >> 1);
  acc = (acc * 33 + 7) ^ (acc >> 1);
  acc = (acc * 33 + 8) ^ (acc >> 1);
  acc = (acc * 33 + 9) ^ (acc >> 1);
  acc = (acc * 33 + 10) ^ (acc >> 1);
  acc = (acc * 33 + 11) ^ (acc >> 1);
  acc = (acc * 33 + 12) ^ (acc >> 1);
  acc = (acc * 33 + 13) ^ (acc >> 1);
  acc = (acc * 33 + 14) ^ (acc >> 1);
  acc = (acc * 33 + 15) ^ (acc >> 1);
  acc = (acc * 33 + 16) ^ (acc >> 1);
  acc = (acc * 33 + 17) ^ (acc >> 1);
  acc = (acc * 33 + 18) ^ (acc >> 1);
  acc = (acc * 33 + 19) ^ (acc >> 1);
  acc = (acc * 33 + 20) ^ (acc >> 1);
  return acc;
}

static int benign_fn_454(int x) {
  int acc = x;
  acc = (acc * 33 + 0) ^ (acc >> 1);
  acc = (acc * 33 + 1) ^ (acc >> 1);
  acc = (acc * 33 + 2) ^ (acc >> 1);
  acc = (acc * 33 + 3) ^ (acc >> 1);
  acc = (acc * 33 + 4) ^ (acc >> 1);
