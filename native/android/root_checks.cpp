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

NativeResult mk(const std::string& id, const std::string& name, int status,
                const std::string& details, const std::string& raw = "") {
    NativeResult r;
    r.id = id;  r.category = CAT_SUBSTRATE;
    r.severity = SEV_MEDIUM;
    r.status = status; r.details = details;

     r.us = 0;
    return r;
}

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

}

NativeResult check_root_su_path() {
    static const char* su_paths[] = {
        "/system/bin/su","/system/xbin/su","/sbin/su","/su/bin/su","/system/sbin/su",
        "/vendor/bin/su","/odm/bin/su","/system/xbin/busybox", nullptr };
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
    return mk("ROOT_SU_PATH", "su binary path", status, d);
}

NativeResult check_root_selinux_domain() {
    FileRead r = read_file_raw("/proc/self/attr/current");
    if (!r.ok) return mk("ROOT_SELINUX_DOMAIN", "selinux domain", STATUS_INCONCLUSIVE, errname(r.err));
    std::string v = trimnl(r.data);
    if (v.empty()) return mk("ROOT_SELINUX_DOMAIN", "selinux domain", STATUS_INCONCLUSIVE, "empty");
    bool bad = v.find("untrusted_app") == std::string::npos;
    return mk("ROOT_SELINUX_DOMAIN", "selinux domain", bad ? STATUS_DETECTED : STATUS_CLEAN, v);
}

NativeResult check_root_proc_status() {
    FileRead st = read_file_raw("/proc/self/status");
    if (!st.ok) return mk("ROOT_PROC_STATUS", "self-status seccomp (non-zygote start)",
                          STATUS_INCONCLUSIVE, errname(st.err));
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
    return mk("ROOT_PROC_STATUS", "self-status seccomp (non-zygote start)", status, d);
}

NativeResult check_root_mount_tokens() {
    FileRead r = read_file_raw("/proc/self/mountinfo");
    if (!r.ok) return mk("ROOT_MOUNT_TOKENS", "mount residue", STATUS_INCONCLUSIVE, errname(r.err));
    int overlay = 0, tmpfs_sys = 0, token = 0, lines = 0; size_t pos = 0;
    while (pos < r.data.size()) {
        size_t nl = r.data.find('\n', pos);
        std::string line = r.data.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? r.data.size() : nl + 1;
        if (line.empty()) continue; lines++;
        bool sysdir = line.find(" /system") != std::string::npos ||
                      line.find(" /vendor") != std::string::npos ||
                      line.find(" /product") != std::string::npos;
        if (line.find(" overlay ") != std::string::npos && sysdir) overlay++;
        if (line.find(" tmpfs ") != std::string::npos && (sysdir || line.find(" /sbin") != std::string::npos)) tmpfs_sys++;
        if (line.find("magisk") != std::string::npos || line.find("/data/adb") != std::string::npos ||
            line.find("KSU") != std::string::npos || line.find("worker") != std::string::npos) token++;
    }
    bool bad = overlay || tmpfs_sys || token;
    return mk("ROOT_MOUNT_TOKENS", "mount residue", bad ? STATUS_DETECTED : STATUS_CLEAN,
              "lines=" + std::to_string(lines) + " overlay_sys=" + std::to_string(overlay) +
              " tmpfs_sys=" + std::to_string(tmpfs_sys) + " tokens=" + std::to_string(token));
}

NativeResult check_root_kernel_string() {
    struct utsname u;
    if (uname(&u) != 0) return mk("ROOT_KERNEL_STRING", "kernel string", STATUS_INCONCLUSIVE, errname(errno));
    std::string rel = u.release, ver = u.version;
    auto tok = [](const std::string& s) {
        return s.find("KSU") != std::string::npos || s.find("ksu") != std::string::npos ||
               s.find("kernelsu") != std::string::npos || s.find("apatch") != std::string::npos ||
               s.find("Magisk") != std::string::npos || s.find("magisk") != std::string::npos; };
    bool bad = tok(rel) || tok(ver);
    return mk("ROOT_KERNEL_STRING", "kernel string", bad ? STATUS_DETECTED : STATUS_CLEAN, "release=" + rel);
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
    return mk("ROOT_MAGISK_DAEMON", "magisk daemon socket", present ? STATUS_DETECTED : STATUS_CLEAN,
              present ? ("connected: " + hit) : "no connect (absent)");
}
