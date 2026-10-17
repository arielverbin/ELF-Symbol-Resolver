/*
 * The program the `ida` tests build for every architecture, then strip:
 * read_request reads a request (recvfrom) after prompting for it, and hands
 * it to parse_request, which counts it in requests_served.
 *
 * noipa keeps GCC from inlining or specializing the two, as a real helper
 * with several callers would be.
 */
#include <stdio.h>
#include <sys/socket.h>

static char request[512];
static int requests_served;

__attribute__((noipa)) static void parse_request(const char *text, long length) {
    requests_served++;
    printf("request #%d: %.*s\n", requests_served, (int)length, text);
}

__attribute__((noipa)) static void read_request(int fd) {
    puts("enter input");
    long length = recvfrom(fd, request, sizeof request, 0, NULL, NULL);
    if (length > 0)
        parse_request(request, length);
}

int main(void) {
    read_request(0);
    return 0;
}
