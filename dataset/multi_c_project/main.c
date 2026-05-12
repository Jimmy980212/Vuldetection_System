void process_user(const char *user);

int main(int argc, char **argv) {
    const char *u = argc > 1 ? argv[1] : "guest";
    process_user(u);
    return 0;
}
