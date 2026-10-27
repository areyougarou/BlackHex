#include "common.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <fcntl.h>
#include <unistd.h>

std::string g_own_process_name;
std::vector<VmaEntry> g_maps;
std::string g_expected_signers;

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

std::vector<VmaEntry> read_maps() {
    std::vector<VmaEntry> result;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return result;

    char line[4352];
    while (fgets(line, sizeof(line), f)) {
        VmaEntry e{};
        int n = 0;

        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %x:%x %" SCNu64 "%n",
                   &e.start, &e.end, e.perms, &e.offset, &e.dev_major, &e.dev_minor,
                   &e.inode, &n) >= 7) {
            const char* p = line + n;
            while (*p == ' ' || *p == '\t') p++;
            e.path.assign(p, strcspn(p, "\r\n"));
            result.push_back(e);
        }
    }
    fclose(f);
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
                if ((unsigned char)c < 0x20) {
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

