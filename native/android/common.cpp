#include "common.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

std::string g_own_process_name;
std::vector<VmaEntry> g_maps;
std::string g_expected_signers;
std::string g_own_package;
int g_target_sdk = 0;

void init_own_process_name() {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return;
    char buf[256] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n > 0) {

        g_own_process_name = std::string(buf);
        size_t nul = g_own_process_name.find('\0');
        if (nul != std::string::npos) g_own_process_name.resize(nul);
    }
}

bool is_own_vma(const std::string& path) {
    if (g_own_process_name.empty() || path.empty()) return false;
    return path.find(g_own_process_name) != std::string::npos;
}

namespace {

bool skip_ws(const char*& p, const char* e) {
    const char* s = p;
    while (p < e && (*p == ' ' || *p == '\t')) p++;
    return p > s;
}

bool number(const char*& p, const char* e, int base, uint64_t& v) {
    const char* s = p;
    v = 0;
    for (; p < e; p++) {
        unsigned d;
        if (*p >= '0' && *p <= '9') d = (unsigned)(*p - '0');
        else if (base == 16 && *p >= 'a' && *p <= 'f') d = (unsigned)(*p - 'a' + 10);
        else if (base == 16 && *p >= 'A' && *p <= 'F') d = (unsigned)(*p - 'A' + 10);
        else break;
        v = v * (uint64_t)base + d;
    }
    return p > s;
}

// One maps line: "start-end perms offset major:minor inode [path]". false = not a maps line.
bool parse_maps_line(const char* p, const char* e, VmaEntry& v) {
    uint64_t major = 0, minor = 0;
    if (!number(p, e, 16, v.start) || p >= e || *p++ != '-' || !number(p, e, 16, v.end) || !skip_ws(p, e)) return false;
    size_t n = 0;
    while (p < e && *p != ' ' && *p != '\t' && n < sizeof(v.perms) - 1) v.perms[n++] = *p++;
    v.perms[n] = 0;
    if (n == 0 || !skip_ws(p, e) || !number(p, e, 16, v.offset) || !skip_ws(p, e)) return false;
    if (!number(p, e, 16, major) || p >= e || *p++ != ':' || !number(p, e, 16, minor)) return false;
    if (!skip_ws(p, e) || !number(p, e, 10, v.inode)) return false;
    v.dev_major = (unsigned)major;
    v.dev_minor = (unsigned)minor;
    skip_ws(p, e);
    const char* q = p;
    while (q < e && *q != '\r') q++;
    v.path.assign(p, (size_t)(q - p));
    return true;
}

}

// Reads the whole map with large reads, then parses each line by hand. The kernel hands back about a
// page per read either way; the parse used sscanf, which cost as much as the kernel's own work and on
// a slow core (Pixel 6, repeat calls) twice as much.
std::vector<VmaEntry> read_maps() {
    std::vector<VmaEntry> result;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return result;
    std::string text;
    size_t len = 0;
    text.resize(256 * 1024);
    for (;;) {
        if (text.size() - len < 64 * 1024) text.resize(text.size() * 2);
        ssize_t n = read(fd, &text[len], text.size() - len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        len += (size_t)n;
    }
    close(fd);
    result.reserve(len / 100);
    const char* p = text.data();
    const char* end = p + len;
    while (p < end) {
        const char* nl = static_cast<const char*>(memchr(p, '\n', (size_t)(end - p)));
        const char* e = nl ? nl : end;
        VmaEntry v{};
        if (parse_maps_line(p, e, v)) result.push_back(std::move(v));
        p = e + 1;
    }
    return result;
}

bool maps_available() { return !g_maps.empty(); }

std::string read_proc_file(const char* path) {
    std::ifstream f(path);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static int g_mem_pipe[2] = {-1, -1};

static bool mem_pipe_open(int fds[2]) {
    return pipe2(fds, O_CLOEXEC | O_NONBLOCK) == 0;
}

void mem_run_begin() {
    if (g_mem_pipe[0] < 0 && !mem_pipe_open(g_mem_pipe)) {
        g_mem_pipe[0] = g_mem_pipe[1] = -1;
    }
}

void mem_run_end() {
    if (g_mem_pipe[0] >= 0) {
        close(g_mem_pipe[0]);
        close(g_mem_pipe[1]);
        g_mem_pipe[0] = g_mem_pipe[1] = -1;
    }
}

ssize_t safe_read_mem_n(uintptr_t addr, void* out, size_t len) {
    int local[2] = {-1, -1};
    bool use_run = g_mem_pipe[0] >= 0;
    int* fds = g_mem_pipe;
    if (!use_run) {
        if (!mem_pipe_open(local)) return -1;
        fds = local;
    }
    uint8_t* dst = static_cast<uint8_t*>(out);
    size_t done = 0;
    bool torn = false;
    while (done < len) {
        size_t chunk = len - done;
        if (chunk > 4096) chunk = 4096;
        ssize_t w = write(fds[1], reinterpret_cast<const void*>(addr + done), chunk);
        if (w <= 0) break;
        ssize_t got = 0;
        while (got < w) {
            ssize_t rd = read(fds[0], dst + done + got, (size_t)(w - got));
            if (rd <= 0) break;
            got += rd;
        }
        done += (size_t)got;
        if (got < w) { torn = true; break; }
        if (w < (ssize_t)chunk) break;
    }
    if (use_run) {
        if (torn) { mem_run_end(); mem_run_begin(); }
    } else {
        close(local[0]);
        close(local[1]);
    }
    return (ssize_t)done;
}

bool safe_read_mem(uintptr_t addr, void* out, size_t len) {
    return safe_read_mem_n(addr, out, len) == (ssize_t)len;
}

size_t read_disk_bytes_for_addr(uintptr_t addr, void* out, size_t len) {
    const VmaEntry* v = nullptr;
    for (const auto& e : g_maps)
        if (addr >= e.start && addr < e.end) { v = &e; break; }
    if (!v || v->path.empty() || v->path[0] == '[') return 0;
    if (v->path.find("memfd:") != std::string::npos) return 0;
    int fd = open(v->path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    off64_t off = (off64_t)(v->offset + (addr - v->start));  // off_t is 32-bit on 32-bit ABIs
    ssize_t n = pread64(fd, out, len, off);
    close(fd);
    return n > 0 ? (size_t)n : 0;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                // Escape control bytes (< 0x20) and every byte 0x7F and above. A non-ASCII path or
                // memfd name would otherwise pass straight into NewStringUTF, where CheckJNI (on in
                // debuggable builds and emulators) aborts the app on a lone or half-cut UTF-8 byte;
                // in a release build the bad string surfaces as a NATIVE_CORE result instead. Escaping
                // each such byte as \u00XX keeps everything handed to JNI plain ASCII. This text is
                // diagnostic only, so a non-ASCII path shown as its byte values, not the real glyphs,
                // is fine.
                if ((unsigned char)c < 0x20 || (unsigned char)c >= 0x7F) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

