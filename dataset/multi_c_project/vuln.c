void read_input(char *out, const char *in);
void handle_request(const char *name);

void process_user(const char *user) {
    char tmp[32];
    read_input(tmp, user);
    handle_request(tmp);
}
