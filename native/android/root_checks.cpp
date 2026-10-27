#include "root_checks.h"
#include <string>
#include <cstring>
#include <cstddef>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace {

struct FileRead { bool ok; int err; std::string data; };
FileRead read_file_raw(const char* path) {
    FileRead r{false, 0, {}};
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) { r.err = errno; return r; }
    char buf[8192]; ssize_t n;
    while ((n = read((int)fd, buf, sizeof buf)) > 0) r.data.append(buf, (size_t)n);
    if (n < 0) r.err = errno; else r.ok = true;
    close((int)fd);
    return r;
}

const char* errname(int e) {
    switch (e) {
        case 0: return "OK"; case EACCES: return "EACCES"; case ENOENT: return "ENOENT";
        case EPERM: return "EPERM"; case EINVAL: return "EINVAL"; case ENOSYS: return "ENOSYS";
        case EFAULT: return "EFAULT"; case ECONNREFUSED: return "ECONNREFUSED";
        case ENOTDIR: return "ENOTDIR"; case EISDIR: return "EISDIR"; case ELOOP: return "ELOOP";
        case ENXIO: return "ENXIO"; case EOPNOTSUPP: return "EOPNOTSUPP"; default: return "errno?";
    }
}

std::string trimnl(std::string s) {
    while (!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' '||s.back()=='\0')) s.pop_back();
    return s;
}

std::vector<std::string> fields(const std::string& s) {
    std::vector<std::string> out; size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && s[i] == ' ') i++;
        size_t j = i;
        while (j < s.size() && s[j] != ' ') j++;
        if (j > i) out.push_back(s.substr(i, j - i));
        i = j;
    }
    return out;
}

bool under(const std::string& p, const char* dir) {
    size_t n = strlen(dir);
    return p.compare(0, n, dir) == 0 && (p.size() == n || p[n] == '/');
}

bool system_path(const std::string& p) {
    for (const char* d : {"/system", "/system_ext", "/vendor", "/product", "/odm"})
        if (under(p, d)) return true;
    return false;
}

std::string option(const std::string& opts, const char* key) {
    std::string k = std::string(key) + "=";
    size_t i = 0;
    while (i < opts.size()) {
        size_t j = opts.find(',', i);
        if (j == std::string::npos) j = opts.size();
        if (opts.compare(i, k.size(), k) == 0) return opts.substr(i + k.size(), j - i - k.size());
        i = j + 1;
    }
    return "";
}

bool stock_overlay(const std::string& super) {
    if (!option(super, "upperdir").empty() || !option(super, "workdir").empty()) return false;
    std::string lower = option(super, "lowerdir");
    if (lower.empty()) return false;
    size_t i = 0;
    while (i < lower.size()) {
        size_t j = lower.find(':', i);
        if (j == std::string::npos) j = lower.size();
        if (!system_path(lower.substr(i, j - i))) return false;
        i = j + 1;
    }
    return true;
}

std::string lower_ascii(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

}

NativeResult check_root_su_path() {
    static const char* su_paths[] = {
        "/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su","/system/sbin/su",
        "/vendor/bin/su","/odm/bin/su", nullptr };
    bool present = false, blocked = false; std::string hit;
    for (int i = 0; su_paths[i]; i++) {
        errno = 0; long rr = syscall(__NR_faccessat, AT_FDCWD, su_paths[i], F_OK); int re = errno;
        if (rr == 0) { present = true; hit += std::string(su_paths[i]) + " "; }
        else if (re != ENOENT) blocked = true;
    }
    int status; std::string d;
    if (present)      { status = STATUS_DETECTED;     d = "su present: " + hit; }
    else if (blocked) { status = STATUS_INCONCLUSIVE; d = "su paths blocked (EACCES) - not a clean read"; }
    else              { status = STATUS_CLEAN;        d = "no su path (all ENOENT)"; }
    return {status, d};
}

NativeResult check_root_selinux_domain() {
    FileRead r = read_file_raw("/proc/self/attr/current");
    if (!r.ok) return {STATUS_INCONCLUSIVE, errname(r.err)};
    std::string v = trimnl(r.data);
    if (v.empty()) return {STATUS_INCONCLUSIVE, "empty"};
    bool bad = v.find("untrusted_app") == std::string::npos;
    return {bad ? STATUS_DETECTED : STATUS_CLEAN, v};
}

NativeResult check_root_proc_status() {
    FileRead st = read_file_raw("/proc/self/status");
    if (!st.ok) return {STATUS_INCONCLUSIVE, errname(st.err)};
    auto field = [&](const char* key) -> std::string {
        size_t p = st.data.find(key); if (p == std::string::npos) return "";
        size_t e = st.data.find('\n', p); return trimnl(st.data.substr(p, e - p)); };
    std::string sec = field("Seccomp:");
    std::string tp  = field("TracerPid:");
    int mode = -1; { size_t c = sec.find(':'); if (c != std::string::npos) {
        std::string v = sec.substr(c + 1); size_t d0 = v.find_first_of("0123456789");
        if (d0 != std::string::npos) mode = v[d0] - '0'; } }
    int status;
    if (mode == 2)      status = STATUS_CLEAN;
    else if (mode == 0) status = STATUS_DETECTED;
    else                status = STATUS_INCONCLUSIVE;
    std::string d = "ppid=" + std::to_string((int)getppid()) + " " + sec + " " + tp +
                    " (seccompMode=" + std::to_string(mode) + ")";
    return {status, d};
}

NativeResult check_root_mount_tokens() {
    FileRead r = read_file_raw("/proc/self/mountinfo");
    if (!r.ok) return {STATUS_INCONCLUSIVE, errname(r.err)};
    struct Mount { std::string dev, root, point, type, source, super; };
    std::vector<Mount> mounts; std::string data_dev; size_t pos = 0;
    while (pos < r.data.size()) {
        size_t nl = r.data.find('\n', pos);
        std::string line = r.data.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? r.data.size() : nl + 1;
        std::vector<std::string> f = fields(line);
        size_t sep = 6;
        while (sep < f.size() && f[sep] != "-") sep++;
        if (f.size() < 5 || sep + 2 >= f.size()) continue;
        Mount m{f[2], f[3], f[4], f[sep + 1], f[sep + 2], sep + 3 < f.size() ? f[sep + 3] : ""};
        if (m.point == "/data") data_dev = m.dev;
        mounts.push_back(m);
    }
    if (mounts.empty()) return {STATUS_INCONCLUSIVE, "no parseable mountinfo line"};
    int overlay = 0, stock = 0, tmpfs_sys = 0, data_bind = 0, token = 0; std::string hit;
    for (const Mount& m : mounts) {
        bool sys = system_path(m.point);
        bool bad = false;
        if (m.type == "overlay" && sys) {
            if (stock_overlay(m.super)) stock++; else { overlay++; bad = true; }
        }
        if (m.type == "tmpfs" && (sys || under(m.point, "/sbin"))) { tmpfs_sys++; bad = true; }
        if (sys && !data_dev.empty() && m.dev == data_dev) { data_bind++; bad = true; }
        std::string src = lower_ascii(m.source);
        if (src == "magisk" || src == "ksu" || src == "apatch" ||
            m.root.find("/adb/modules") != std::string::npos || m.root.find("/data/adb") != std::string::npos ||
            m.point.find("/data/adb") != std::string::npos || m.point.find("/debug_ramdisk") != std::string::npos ||
            m.super.find("/data/adb") != std::string::npos || m.super.find(".magisk") != std::string::npos) {
            token++; bad = true;
        }
        if (bad && hit.size() < 400) hit += " " + m.point + "(" + m.type + "," + m.source + ")";
    }
    bool bad = overlay || tmpfs_sys || data_bind || token;
    return {bad ? STATUS_DETECTED : STATUS_CLEAN,
            "lines=" + std::to_string(mounts.size()) + " overlay_sys=" + std::to_string(overlay) +
              " stock_overlay=" + std::to_string(stock) + " tmpfs_sys=" + std::to_string(tmpfs_sys) +
              " data_bind=" + std::to_string(data_bind) + " tokens=" + std::to_string(token) + hit};
}

NativeResult check_root_kernel_string() {
    struct utsname u;
    if (uname(&u) != 0) return {STATUS_INCONCLUSIVE, errname(errno)};
    std::string rel = u.release, ver = u.version;
    auto tok = [](const std::string& s) {
        return s.find("KSU") != std::string::npos || s.find("ksu") != std::string::npos ||
               s.find("kernelsu") != std::string::npos || s.find("apatch") != std::string::npos ||
               s.find("Magisk") != std::string::npos || s.find("magisk") != std::string::npos; };
    bool bad = tok(rel) || tok(ver);
    return {bad ? STATUS_DETECTED : STATUS_CLEAN, "release=" + rel};
}

NativeResult check_root_magisk_daemon() {
    static const char* names[] = { "magisk","magiskd","magisksu","zygisk_lp64","zygisk_next","apatch_daemon", nullptr };
    bool present = false; std::string hit;
    for (int i = 0; names[i]; i++) {
        int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); if (s < 0) continue;
        struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
        size_t nl = strlen(names[i]); a.sun_path[0] = 0; memcpy(a.sun_path + 1, names[i], nl);
        socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + nl);
        errno = 0; int rc = connect(s, (struct sockaddr*)&a, len); close(s);
        if (rc == 0) { present = true; hit += std::string(names[i]) + " "; }
    }
    return {present ? STATUS_DETECTED : STATUS_CLEAN,
            present ? ("connected: " + hit) : "no connect (absent)"};
}
