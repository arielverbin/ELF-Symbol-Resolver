from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from demo_resolver import DemoResolver

NAME = "firmware"


def resolve(resolver: DemoResolver) -> None:
    # (On ARM, -O2 reaches globals through a section anchor: see the README's known limitations.)

    # The globals holding the default hostname: the live settings, and the factory defaults.
    hostname_holders = GlobalVar().references(String("thermostat-factory-default"))

    # Of the two, the live settings: those the shell's status command shows the hostname of.
    status = Function().references(String().matching("^%s: target"))
    settings = hostname_holders.referenced_by(status)

    # The logger, formatting '[severity] message', and the globals it uses: the ring buffer's
    # lines, its next line, and the severities' names.
    log = Function().references(String("[%s] %s"))
    log_state = GlobalVar().referenced_by(log)

    # What prints the log back: a function calling puts, reading what the logger writes. What both
    # use is the ring buffer.
    dump = Function().calls(PLTEntry("puts")).references(log_state)
    ring_buffer = log_state.referenced_by(dump)

    # The sensor's calibration table: the global read where a reading is converted.
    calibration = GlobalVar().referenced_by(Function().references(String("sensor reading out of range")))

    # The boot counter: a static local to the function logging 'boot #...'. (On ARM, the anchor too.)
    boot_count = GlobalVar().referenced_by(Function().references(String().matching("^boot #%u")))

    # What the status shows of the heating's control loop: its mode, the time spent heating, and
    # the settings' target temperature, a field IDA typed as an item of its own.
    regulate = Function().references(String("heating on"))
    heating_state = GlobalVar().referenced_by(regulate).referenced_by(status)

    # The shell's table of commands: the global pointing at the first command's name.
    commands = GlobalVar().references(String("status"))

    resolver.resolve_all(hostname_holders, ["device::settings", "device::factory_defaults"])
    resolver.resolve(status, "shell::show_status")
    resolver.resolve(settings, "device::settings")
    resolver.resolve(log, "logbook::log")
    resolver.resolve_all(log_state, ["logbook::lines", "logbook::next_line", "logbook::severity_names"])
    resolver.resolve(dump, "logbook::dump")
    resolver.resolve_all(ring_buffer, ["logbook::lines", "logbook::next_line"])
    resolver.resolve(calibration, "device::calibration")
    resolver.resolve_all(boot_count, ["boot()::boot_count"])
    resolver.resolve(regulate, "control::regulate")
    resolver.resolve_all(heating_state, ["device::settings", "device::mode", "device::heating_seconds"])
    resolver.resolve(commands, "shell::commands")


SOURCE = r"""
// A thermostat's firmware: settings with factory defaults, a calibration table for
// its temperature sensor, the heating's state, a ring buffer of log lines, a boot
// counter, and a shell whose commands sit in a table.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

// No inlining, cloning nor folding: each function stays one, as a function with many callers would.
#define KEEP __attribute__((noipa))

namespace device {

struct Settings {
    const char* hostname;
    int target_temperature;  // in tenths of a degree
    int hysteresis;
    unsigned report_interval;
    bool heating_enabled;
};

Settings settings = {"thermostat-factory-default", 215, 5, 60, true};
Settings factory_defaults = {"thermostat-factory-default", 215, 5, 60, true};  // in flash: provisioning rewrites it

// The sensor's raw reading (0-255), in tenths of a degree: one entry per 16 steps.
const std::int16_t calibration[17] = {
    -400, -310, -225, -145, -70, 0, 65, 130, 195, 260, 330, 405, 485, 570, 660, 760, 870,
};

enum class Mode : std::uint8_t { Idle, Heating, Fault };

static Mode mode;
static unsigned heating_seconds;

}  // namespace device

namespace logbook {

constexpr int LINES = 16;
constexpr int WIDTH = 96;

static char lines[LINES][WIDTH];
static unsigned next_line;
const char* const severity_names[] = {"debug", "info", "warning", "error"};

KEEP void log(int severity, const char* message) {
    std::snprintf(lines[next_line % LINES], WIDTH, "[%s] %s", severity_names[severity & 3], message);
    next_line++;
}

KEEP void dump() {
    unsigned first = next_line > LINES ? next_line - LINES : 0;
    for (unsigned line = first; line < next_line; ++line)
        std::puts(lines[line % LINES]);
}

}  // namespace logbook

namespace sensor {

KEEP int read_raw() {
    int fd = open("/dev/adc0", O_RDONLY);
    if (fd < 0) {
        logbook::log(3, "cannot open the temperature sensor");
        return -1;
    }
    unsigned char raw = 0;
    ssize_t got = read(fd, &raw, 1);
    close(fd);
    return got == 1 ? raw : -1;
}

// Interpolated between the two calibration points around it.
KEEP int to_tenths(int raw) {
    if (raw < 0 || raw > 255) {
        logbook::log(3, "sensor reading out of range");
        return -1000;
    }
    int index = raw / 16, offset = raw % 16;
    int low = device::calibration[index], high = device::calibration[index + 1];
    return low + (high - low) * offset / 16;
}

}  // namespace sensor

namespace control {

KEEP void regulate(int temperature) {
    using device::Mode;
    const device::Settings& settings = device::settings;
    if (temperature <= -1000) {
        device::mode = Mode::Fault;
        logbook::log(3, "sensor fault: heating stopped");
        return;
    }
    if (settings.heating_enabled && temperature < settings.target_temperature - settings.hysteresis) {
        if (device::mode != Mode::Heating)
            logbook::log(1, "heating on");
        device::mode = Mode::Heating;
        device::heating_seconds += settings.report_interval;
    } else if (temperature > settings.target_temperature + settings.hysteresis) {
        if (device::mode == Mode::Heating)
            logbook::log(1, "heating off");
        device::mode = Mode::Idle;
    }
}

}  // namespace control

namespace shell {

struct Command {
    const char* name;
    const char* help;
    void (*run)(const char* argument);
};

KEEP void show_status(const char*) {
    std::printf("%s: target %d.%d C, mode %d, heated for %u s\n", device::settings.hostname,
                device::settings.target_temperature / 10, device::settings.target_temperature % 10,
                static_cast<int>(device::mode), device::heating_seconds);
}

KEEP void set_target(const char* argument) {
    int tenths = std::atoi(argument);
    if (tenths < 50 || tenths > 300) {
        logbook::log(2, "target temperature out of range");
        return;
    }
    device::settings.target_temperature = tenths;
    logbook::log(1, "target temperature changed");
}

KEEP void reset_settings(const char*) {
    device::settings = device::factory_defaults;
    logbook::log(2, "settings reset to the factory defaults");
}

KEEP void show_log(const char*) {
    logbook::dump();
}

KEEP void show_help(const char*);

const Command commands[] = {
    {"status", "show the temperature and the heating's state", show_status},
    {"set", "set the target temperature, in tenths of a degree", set_target},
    {"reset", "restore the factory defaults", reset_settings},
    {"log", "show the last log lines", show_log},
    {"help", "list the commands", show_help},
};

KEEP void show_help(const char*) {
    for (const Command& command : commands)
        std::printf("  %-8s %s\n", command.name, command.help);
}

KEEP bool execute(const char* line) {
    char name[16] = {};
    const char* space = std::strchr(line, ' ');
    unsigned length = static_cast<unsigned>(space != nullptr ? space - line : std::strlen(line));
    if (length >= sizeof name)
        return false;
    std::memcpy(name, line, length);
    for (const Command& command : commands) {
        if (std::strcmp(command.name, name) == 0) {
            command.run(space != nullptr ? space + 1 : "");
            return true;
        }
    }
    logbook::log(2, "unknown command");
    return false;
}

}  // namespace shell

KEEP unsigned boot() {
    static unsigned boot_count;
    ++boot_count;
    char message[64];
    std::snprintf(message, sizeof message, "boot #%u, firmware 3.1.4", boot_count);
    logbook::log(1, message);
    return boot_count;
}

int main(int argc, char** argv) {
    boot();
    control::regulate(sensor::to_tenths(sensor::read_raw()));
    for (int i = 1; i < argc; ++i)
        shell::execute(argv[i]);
    return 0;
}
"""
