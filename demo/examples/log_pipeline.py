from elfresolver.symbols import Function, GlobalVar, PLTEntry
from demo_resolver import DemoResolver

NAME = "log_pipeline"


def resolve(resolver: DemoResolver) -> None:
    # The pipeline's start: the function opening a log file. (32-bit glibc calls fopen fopen64,
    # where files' offsets are 64-bit.)
    watch = Function().calls(PLTEntry().matching("^fopen(64)?$"))

    # The stage it feeds each line to: what it calls directly, imports aside.
    first_stage = Function().called_by(watch)

    # Every stage of the pipeline: what it calls, at any depth.
    stages = Function().called_by(watch, max_depth=None)

    # What raises an alert: the function opening syslog. Then what may raise one within two calls,
    # and every path to one, at any depth, up to main.
    alert = Function().calls(PLTEntry("openlog"))
    near_alert = Function().calls(alert, max_depth=2)
    to_alert = Function().calls(alert, max_depth=None)

    # The parsing stages: below the start, calling sscanf (__isoc23_sscanf, as glibc 2.38 names it).
    parsers = stages.calls(PLTEntry().matching("sscanf"))

    # The counters an alert is raised on: the globals checked right before raising it.
    alert_counters = GlobalVar().referenced_by(Function().calls(alert))

    resolver.resolve(watch, "logwatch::watch_file")
    resolver.resolve(first_stage, "logwatch::process_line")
    resolver.resolve_all(stages, [
        "logwatch::process_line", "logwatch::parse_line", "logwatch::parse_timestamp", "logwatch::normalize_path",
        "logwatch::count", "logwatch::check_thresholds", "logwatch::raise_alert",
    ])
    resolver.resolve(alert, "logwatch::raise_alert")
    resolver.resolve_all(near_alert, ["logwatch::check_thresholds", "logwatch::count"])
    resolver.resolve_all(to_alert, [
        "logwatch::check_thresholds", "logwatch::count", "logwatch::process_line", "logwatch::watch_file", "main",
    ])
    resolver.resolve_all(parsers, ["logwatch::parse_line", "logwatch::parse_timestamp"])
    resolver.resolve_all(alert_counters, ["logwatch::lines_read", "logwatch::lines_rejected", "logwatch::server_errors"])


SOURCE = r"""
// logwatch: reads a web server's access logs, line by line, through a pipeline of
// stages: parse each line, read its timestamp, normalize its path, then count it.
// When server errors pile up, it raises an alert to syslog.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <syslog.h>

// No inlining, cloning nor folding: each function stays one, as a function with many callers would.
#define KEEP __attribute__((noipa))

namespace logwatch {

struct Entry {
    char address[48];
    char method[8];
    char path[128];
    int status;
    long bytes;
    std::time_t when;
};

long lines_read;
long lines_rejected;
long server_errors;
long bytes_served;
int status_counts[6];  // by the status' first digit: 1xx to 5xx

KEEP void raise_alert(const char* reason, long count) {
    openlog("logwatch", LOG_PID, LOG_DAEMON);
    syslog(LOG_WARNING, "%s: %ld so far", reason, count);
    closelog();
}

KEEP void check_thresholds() {
    if (server_errors > 0 && server_errors % 10 == 0)
        raise_alert("server errors", server_errors);
    if (lines_rejected * 4 > lines_read)
        raise_alert("unparsable lines", lines_rejected);
}

KEEP void count(const Entry& entry) {
    bytes_served += entry.bytes;
    int family = entry.status / 100;
    if (family >= 1 && family <= 5)
        status_counts[family]++;
    if (family == 5) {
        server_errors++;
        check_thresholds();
    }
}

// "[10/Oct/2023:13:55:36": the day, the month's name, the year, and the time.
KEEP std::time_t parse_timestamp(const char* text) {
    static const char* const months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    std::tm time{};
    char month[4] = {};
    if (std::sscanf(text, "[%2d/%3c/%4d:%2d:%2d:%2d", &time.tm_mday, month, &time.tm_year,
                    &time.tm_hour, &time.tm_min, &time.tm_sec) != 6)
        return -1;
    time.tm_mon = -1;
    for (int i = 0; i < 12; ++i)
        if (std::strncmp(month, months[i], 3) == 0)
            time.tm_mon = i;
    if (time.tm_mon < 0)
        return -1;
    time.tm_year -= 1900;
    return timegm(&time);
}

// Without its query, in lower case: "/Index.html?ref=x" counts as "/index.html".
KEEP bool normalize_path(char* path) {
    if (char* query = std::strchr(path, '?'))
        *query = '\0';
    for (char* c = path; *c != '\0'; ++c)
        if (*c >= 'A' && *c <= 'Z')
            *c = static_cast<char>(*c - 'A' + 'a');
    return path[0] == '/';
}

// 127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
KEEP bool parse_line(const char* line, Entry& entry) {
    char timestamp[32];
    if (std::sscanf(line, "%47s - - %31s %*s \"%7s %127s %*[^\"]\" %d %ld", entry.address, timestamp,
                    entry.method, entry.path, &entry.status, &entry.bytes) != 6)
        return false;
    entry.when = parse_timestamp(timestamp);
    return entry.when != -1 && normalize_path(entry.path);
}

KEEP void process_line(const char* line) {
    lines_read++;
    Entry entry{};
    if (!parse_line(line, entry)) {
        lines_rejected++;
        return;
    }
    count(entry);
}

KEEP bool watch_file(const char* path) {
    std::FILE* file = std::fopen(path, "r");
    if (file == nullptr) {
        std::perror(path);
        return false;
    }
    char line[1024];
    while (std::fgets(line, sizeof line, file) != nullptr)
        process_line(line);
    std::fclose(file);
    return true;
}

KEEP void print_summary() {
    std::printf("%ld lines, %ld rejected, %ld bytes served\n", lines_read, lines_rejected, bytes_served);
    for (int family = 1; family <= 5; ++family)
        std::printf("  %dxx: %d\n", family, status_counts[family]);
}

}  // namespace logwatch

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        logwatch::watch_file(argv[i]);
    logwatch::print_summary();
    return 0;
}
"""
