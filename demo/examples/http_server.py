from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from demo_resolver import DemoResolver

NAME = "http_server"


def resolve(resolver: DemoResolver) -> None:
    # Anchored on imports: the socket's setup calls bind and listen; serving a client receives.
    listener = Function().calls(PLTEntry("bind")).calls(PLTEntry("listen"))
    serve = Function().calls(PLTEntry("recv"))

    # Anchored on a string: what writes the responses formats their status line.
    respond = Function().references(String().matching(r"^HTTP/1\.0 %d"))

    # A hop away: what respond sends with, and the parser serve calls, looking for line ends.
    send_all = Function().called_by(respond).calls(PLTEntry("send"))
    parse = Function().called_by(serve).calls(PLTEntry("strstr"))

    # Another hop: the request line's parser, which checks the protocol's version.
    parse_line = Function().called_by(parse).references(String("HTTP/1."))

    # The routes' handlers: the functions a global (the routing table) points at, which respond.
    handlers = Function().referenced_by(GlobalVar()).calls(respond)

    # Of them, the /status page: the one responding with the statistics' JSON.
    status = handlers.references(String().matching('"bytes_sent"'))

    # The statistics' counters: the globals /status reads; of them, those serve updates too.
    # (On ARM, -O2 reaches globals through a section anchor: see the README's known limitations.)
    counters = GlobalVar().referenced_by(status)
    counted_on_arrival = counters.referenced_by(serve)

    # The server's name, as the Server header gives it: the global pointing at it.
    server_name = GlobalVar().references(String().matching("^tinyhttpd/"))

    # Every function reporting a failed system call.
    error_paths = Function().calls(PLTEntry("perror"))

    resolver.resolve(listener, "http::open_listener")
    resolver.resolve(serve, "http::serve_client")
    resolver.resolve(respond, "http::send_response")
    resolver.resolve(send_all, "http::send_all")
    resolver.resolve(parse, "http::parse_request")
    resolver.resolve(parse_line, "http::parse_request_line")
    resolver.resolve_all(handlers, ["http::handle_index", "http::handle_status", "http::handle_echo"])
    resolver.resolve(status, "http::handle_status")
    resolver.resolve_all(counters, ["http::requests_total", "http::bad_requests", "http::pages_not_found", "http::bytes_sent"])
    resolver.resolve_all(counted_on_arrival, ["http::requests_total", "http::bad_requests"])
    resolver.resolve(server_name, "http::server_name")
    resolver.resolve_all(error_paths, ["http::open_listener", "http::send_all"])


SOURCE = r"""
// tinyhttpd: a small HTTP/1.0 server, of the kind a router's or a camera's firmware
// runs. It parses requests by hand, routes them through a table of handlers, and
// counts what it serves in global counters, which /status reports.

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

// No inlining, cloning nor folding: each function stays one, as a function with many callers would.
#define KEEP __attribute__((noipa))

namespace http {

constexpr int MAX_REQUEST = 4096;
constexpr int MAX_HEADERS = 16;

struct Header {
    const char* name;
    const char* value;
};

struct Request {
    char method[8];
    char path[256];
    Header headers[MAX_HEADERS];
    int header_count;
    const char* body;
};

using Handler = void (*)(int client, const Request& request);

struct Route {
    const char* path;
    const char* method;
    Handler handler;
};

// What the server counts, as /status reports it.
unsigned long requests_total;
unsigned long bad_requests;
unsigned long pages_not_found;
unsigned long bytes_sent;

char receive_buffer[MAX_REQUEST];
int listen_port = 8080;
const char* server_name = "tinyhttpd/1.2";

KEEP void log_access(const Request& request, int status) {
    std::printf("[access] %-6s %-24s %d\n", request.method, request.path, status);
}

KEEP bool send_all(int client, const char* data, unsigned length) {
    while (length > 0) {
        ssize_t sent = send(client, data, length, MSG_NOSIGNAL);
        if (sent <= 0) {
            std::perror("send");
            return false;
        }
        data += sent;
        length -= static_cast<unsigned>(sent);
        bytes_sent += static_cast<unsigned long>(sent);
    }
    return true;
}

KEEP void send_response(int client, int status, const char* reason, const char* content_type, const char* body) {
    char head[512];
    unsigned body_length = static_cast<unsigned>(std::strlen(body));
    int head_length = std::snprintf(head, sizeof head,
        "HTTP/1.0 %d %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
        status, reason, server_name, content_type, body_length);
    if (head_length > 0 && send_all(client, head, static_cast<unsigned>(head_length)))
        send_all(client, body, body_length);
}

KEEP const char* find_header(const Request& request, const char* name) {
    for (int i = 0; i < request.header_count; ++i)
        if (strcasecmp(request.headers[i].name, name) == 0)
            return request.headers[i].value;
    return nullptr;
}

// "GET /status HTTP/1.0": the method, the path, and a version this server speaks.
KEEP bool parse_request_line(char* line, Request& request) {
    char* space = std::strchr(line, ' ');
    if (space == nullptr || space - line >= static_cast<long>(sizeof request.method))
        return false;
    std::memcpy(request.method, line, static_cast<unsigned>(space - line));
    request.method[space - line] = '\0';
    char* path = space + 1;
    char* version = std::strchr(path, ' ');
    if (version == nullptr || std::strncmp(version + 1, "HTTP/1.", 7) != 0)
        return false;
    *version = '\0';
    if (path[0] != '/' || std::strlen(path) >= sizeof request.path)
        return false;
    std::strcpy(request.path, path);
    return true;
}

// The request line, then "Name: value" headers up to an empty line, then the body.
KEEP bool parse_request(char* text, Request& request) {
    char* line_end = std::strstr(text, "\r\n");
    if (line_end == nullptr)
        return false;
    *line_end = '\0';
    if (!parse_request_line(text, request))
        return false;
    request.header_count = 0;
    char* line = line_end + 2;
    while ((line_end = std::strstr(line, "\r\n")) != nullptr && line_end != line) {
        *line_end = '\0';
        char* colon = std::strchr(line, ':');
        if (colon != nullptr && request.header_count < MAX_HEADERS) {
            *colon = '\0';
            char* value = colon + 1;
            while (*value == ' ' || *value == '\t')
                ++value;
            request.headers[request.header_count++] = {line, value};
        }
        line = line_end + 2;
    }
    request.body = line_end != nullptr ? line_end + 2 : line;
    return true;
}

KEEP void handle_index(int client, const Request&) {
    send_response(client, 200, "OK", "text/html", "<html><body><h1>It works!</h1></body></html>");
}

KEEP void handle_status(int client, const Request&) {
    char body[256];
    std::snprintf(body, sizeof body,
        "{\"requests\": %lu, \"bad_requests\": %lu, \"not_found\": %lu, \"bytes_sent\": %lu}",
        requests_total, bad_requests, pages_not_found, bytes_sent);
    send_response(client, 200, "OK", "application/json", body);
}

KEEP void handle_echo(int client, const Request& request) {
    const char* agent = find_header(request, "User-Agent");
    send_response(client, 200, "OK", "text/plain", agent != nullptr ? agent : request.body);
}

const Route routes[] = {
    {"/", "GET", handle_index},
    {"/status", "GET", handle_status},
    {"/echo", "POST", handle_echo},
};

KEEP void route(int client, const Request& request) {
    for (const Route& candidate : routes) {
        if (std::strcmp(candidate.path, request.path) != 0)
            continue;
        if (std::strcmp(candidate.method, request.method) != 0) {
            send_response(client, 405, "Method Not Allowed", "text/plain", "method not allowed");
            log_access(request, 405);
            return;
        }
        candidate.handler(client, request);
        log_access(request, 200);
        return;
    }
    pages_not_found++;
    send_response(client, 404, "Not Found", "text/plain", "no such page");
    log_access(request, 404);
}

KEEP void serve_client(int client) {
    ssize_t length = recv(client, receive_buffer, sizeof receive_buffer - 1, 0);
    if (length <= 0)
        return;
    receive_buffer[length] = '\0';
    requests_total++;
    Request request{};
    if (!parse_request(receive_buffer, request)) {
        bad_requests++;
        send_response(client, 400, "Bad Request", "text/plain", "malformed request");
        return;
    }
    route(client, request);
}

KEEP int open_listener(int port) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        std::perror("socket");
        std::exit(EXIT_FAILURE);
    }
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(static_cast<unsigned short>(port));
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof address) < 0 || listen(listener, 16) < 0) {
        std::perror("bind");
        std::exit(EXIT_FAILURE);
    }
    return listener;
}

}  // namespace http

int main() {
    int listener = http::open_listener(http::listen_port);
    std::printf("%s listening on port %d\n", http::server_name, http::listen_port);
    for (;;) {
        int client = accept(listener, nullptr, nullptr);
        if (client < 0)
            continue;
        http::serve_client(client);
        close(client);
    }
}
"""
