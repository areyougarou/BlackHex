#include "common.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

std::string g_own_process_name;
std::vector<VmaEntry> g_maps;
std::string g_signer_baseline;

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

        if (sscanf(line, "%lx-%lx %7s %lx %x:%x %lu%n",
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

std::string read_proc_file(const char* path) {
    std::ifstream f(path);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool safe_read_mem(uintptr_t addr, void* out, size_t len) {
    static int mem_fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (mem_fd < 0) return false;
    ssize_t n = pread(mem_fd, out, len, (off_t)addr);
    return n == (ssize_t)len;
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

std::string results_to_json(const std::vector<NativeResult>& results) {
    std::ostringstream ss;
    ss << "[";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        if (i > 0) ss << ",";
        ss << "{"
           << "\"id\":\"" << json_escape(r.id) << "\","
           << "\"category\":\"" << r.category << "\","
           << "\"severity\":\"" << r.severity << "\","
           << "\"status\":" << r.status << ","
           << "\"us\":" << r.us << ","
           << "\"certainty\":" << (r.certainty == CERT_UNSET ? CERT_WEAK : r.certainty) << ","
           << "\"details\":\"" << json_escape(r.details) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}
